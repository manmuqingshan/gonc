package acl

// VERSION 1.2.0 (Inbound/Outbound Allowlist Support)
import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// 定义动作常量
const (
	ActionNone  = 0
	ActionDeny  = 1 // 拒绝
	ActionAllow = 2 // 允许 (例外)
)

// ============================================================================
//  Radix Tree (基数树) - 用于高效的 IP/CIDR 查询
//  升级：支持最长前缀匹配 (LPM) 和 动作区分
// ============================================================================

// radixNode 代表基数树中的一个节点。
type radixNode struct {
	// children[0] 代表比特 0, children[1] 代表比特 1。
	children [2]*radixNode
	// action 标记该节点是否为一个规则的终点，以及规则的类型 (Allow/Deny)。
	// 0 表示此处无规则。
	action int
}

// radixTree 是一个为 IP 前缀设计的二叉基数树。
type radixTree struct {
	root *radixNode
}

// newRadixTree 创建一个新的空基数树。
func newRadixTree() *radixTree {
	return &radixTree{root: &radixNode{}}
}

// Insert 将一个 CIDR 前缀添加到树中，并指定动作 (Allow 或 Deny)。
func (t *radixTree) Insert(ipNet *net.IPNet, action int) {
	node := t.root
	// 从掩码获取前缀长度
	prefixLen, _ := ipNet.Mask.Size()
	// 遍历网络 IP 地址的每一个比特位
	for i := 0; i < prefixLen; i++ {
		// 获取位置 i 的比特值 (0 or 1)
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (ipNet.IP[byteIndex] >> bitIndex) & 1

		// 如果子节点不存在，则创建它
		if node.children[bit] == nil {
			node.children[bit] = &radixNode{}
		}
		node = node.children[bit]
	}
	// 标记此前缀的结束及其动作
	// 注意：后加载的规则会覆盖先加载的同CIDR规则
	node.action = action
}

// Match 检查一个 IP 地址匹配到的动作。
// 采用最长前缀匹配 (Longest Prefix Match) 原则。
// 返回: ActionNone, ActionDeny, 或 ActionAllow
func (t *radixTree) Match(ip net.IP) int {
	node := t.root
	lastMatchAction := ActionNone

	// IP 地址的总位数 (IPv4 是 32, IPv6 是 128)
	totalBits := len(ip) * 8
	for i := 0; i < totalBits; i++ {
		// 如果当前节点有一个规则动作，记录它。
		// 我们继续向下遍历以寻找更长（更具体）的匹配。
		if node.action != ActionNone {
			lastMatchAction = node.action
		}

		// 获取当前 IP 位的值
		byteIndex := i / 8
		bitIndex := 7 - (i % 8)
		bit := (ip[byteIndex] >> bitIndex) & 1

		// 移动到下一个节点
		node = node.children[bit]
		if node == nil {
			// 路径中断，返回目前为止找到的最长匹配动作
			return lastMatchAction
		}
	}
	// 检查最后一个节点是否有动作 (例如 /32 或 /128 的精确匹配)
	if node.action != ActionNone {
		lastMatchAction = node.action
	}
	return lastMatchAction
}

// ============================================================================
//  Domain Rule Set (域名规则集) - 内部辅助结构
// ============================================================================

// domainRuleSet 存储一组域名匹配规则（无论是黑名单还是白名单都复用此结构）。
type domainRuleSet struct {
	fullWildcard    bool
	exactMatches    map[string]struct{} // 精确匹配
	prefixWildcards map[string]struct{} // 前缀通配符, 例如 "example.*"
	suffixWildcards map[string]struct{} // 后缀通配符, 例如 "*.example.com"
}

func newDomainRuleSet() *domainRuleSet {
	return &domainRuleSet{
		exactMatches:    make(map[string]struct{}),
		prefixWildcards: make(map[string]struct{}),
		suffixWildcards: make(map[string]struct{}),
	}
}

func (s *domainRuleSet) add(rule string) {
	if rule == "*" {
		s.fullWildcard = true
		return
	}
	if strings.HasPrefix(rule, "*.") {
		s.suffixWildcards[rule[2:]] = struct{}{}
		return
	}
	if strings.HasSuffix(rule, ".*") {
		s.prefixWildcards[rule[:len(rule)-2]] = struct{}{}
		return
	}
	s.exactMatches[rule] = struct{}{}
}

func (s *domainRuleSet) match(domain string) bool {
	if s.fullWildcard {
		return true
	}
	if _, ok := s.exactMatches[domain]; ok {
		return true
	}

	parts := strings.Split(domain, ".")

	// 检查前缀通配符
	if len(parts) > 0 {
		if _, ok := s.prefixWildcards[parts[0]]; ok {
			return true
		}
	}

	// 检查后缀通配符
	for i := 1; i < len(parts); i++ {
		suffix := strings.Join(parts[i:], ".")
		if _, ok := s.suffixWildcards[suffix]; ok {
			return true
		}
	}
	return false
}

// ============================================================================
//  Domain Matcher (域名匹配器) - 用于高效的出站域名查询
//  升级：支持 Exception (Allow) 优先逻辑
// ============================================================================

// domainMatcher 持有用于出站域名匹配的规则。
type domainMatcher struct {
	allowRules *domainRuleSet // 存储以 "!" 开头的例外规则
	denyRules  *domainRuleSet // 存储普通拒绝规则
}

// newDomainMatcher 创建一个新的域名匹配器。
func newDomainMatcher() *domainMatcher {
	return &domainMatcher{
		allowRules: newDomainRuleSet(),
		denyRules:  newDomainRuleSet(),
	}
}

// AddRule 将一条域名规则添加到匹配器中。
// 如果规则以 "!" 开头，则添加到允许列表。
func (dm *domainMatcher) AddRule(rule string) {
	rule = strings.ToLower(strings.TrimSpace(rule))
	if len(rule) == 0 {
		return
	}

	// 检查是否为例外规则
	if strings.HasPrefix(rule, "!") {
		realRule := strings.TrimSpace(rule[1:])
		if len(realRule) > 0 {
			dm.allowRules.add(realRule)
		}
	} else {
		dm.denyRules.add(rule)
	}
}

// Match 检查一个域名是否应该被拒绝。
// 逻辑：如果匹配 Allow 规则 -> 返回 False (不拒绝)
//
//	如果匹配 Deny 规则  -> 返回 True  (拒绝)
//	否则               -> 返回 False
func (dm *domainMatcher) Match(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))

	// 1. 优先检查例外列表 (Whitelist)
	// 如果在例外列表中找到，直接返回 false (不拒绝)，忽略后续的黑名单
	if dm.allowRules.match(domain) {
		return false
	}

	// 2. 检查黑名单 (Blacklist)
	if dm.denyRules.match(domain) {
		return true
	}

	return false
}

type portRange struct {
	start uint16
	end   uint16
}

// endpointAllowlist stores exact IP/domain hosts and their allowed port ranges.
// Host wildcards and CIDRs are intentionally unsupported here: allowlist entries
// must identify one concrete host.
type endpointAllowlist struct {
	ranges map[string][]portRange
}

func newEndpointAllowlist() *endpointAllowlist {
	return &endpointAllowlist{ranges: make(map[string][]portRange)}
}

func normalizeEndpointHost(host string) (key string, normalized string, err error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", "", fmt.Errorf("host is empty")
	}

	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		ip = ip.Unmap()
		normalized = ip.String()
		return "ip:" + normalized, normalized, nil
	}

	if strings.ContainsAny(host, "*/") {
		return "", "", fmt.Errorf("host must be an exact IP or domain")
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", "", fmt.Errorf("domain is empty")
	}
	if strings.ContainsAny(host, " \t\r\n[]:") {
		return "", "", fmt.Errorf("invalid domain %q", host)
	}
	if len(host) > 253 {
		return "", "", fmt.Errorf("domain is longer than 253 bytes")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return "", "", fmt.Errorf("invalid domain label in %q", host)
		}
		for index, r := range label {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
				continue
			}
			if r == '-' && index > 0 && index < len(label)-1 {
				continue
			}
			return "", "", fmt.Errorf("invalid character %q in domain %q", r, host)
		}
	}
	normalized = strings.ToLower(host)
	return "domain:" + normalized, normalized, nil
}

func parsePortRange(spec string) (portRange, error) {
	spec = strings.TrimSpace(spec)
	parts := strings.Split(spec, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return portRange{}, fmt.Errorf("invalid port or port range %q", spec)
	}

	parsePort := func(value string) (uint16, error) {
		value = strings.TrimSpace(value)
		if value == "" {
			return 0, fmt.Errorf("port is empty")
		}
		for _, r := range value {
			if r < '0' || r > '9' {
				return 0, fmt.Errorf("port %q must be numeric", value)
			}
		}
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return 0, fmt.Errorf("port %q must be between 1 and 65535", value)
		}
		return uint16(port), nil
	}

	start, err := parsePort(parts[0])
	if err != nil {
		return portRange{}, err
	}
	end := start
	if len(parts) == 2 {
		end, err = parsePort(parts[1])
		if err != nil {
			return portRange{}, err
		}
		if start > end {
			return portRange{}, fmt.Errorf("port range start %d is greater than end %d", start, end)
		}
	}
	return portRange{start: start, end: end}, nil
}

func parseOutboundAllowRule(rule string) (string, portRange, error) {
	host, portSpec, err := net.SplitHostPort(strings.TrimSpace(rule))
	if err != nil {
		return "", portRange{}, fmt.Errorf("expected host:port or host:start-end: %w", err)
	}
	key, _, err := normalizeEndpointHost(host)
	if err != nil {
		return "", portRange{}, err
	}
	ports, err := parsePortRange(portSpec)
	if err != nil {
		return "", portRange{}, err
	}
	return key, ports, nil
}

func (l *endpointAllowlist) add(key string, ports portRange) {
	l.ranges[key] = append(l.ranges[key], ports)
}

func (l *endpointAllowlist) finalize() {
	for key, ranges := range l.ranges {
		sort.Slice(ranges, func(i, j int) bool {
			if ranges[i].start == ranges[j].start {
				return ranges[i].end < ranges[j].end
			}
			return ranges[i].start < ranges[j].start
		})

		merged := ranges[:0]
		for _, current := range ranges {
			if len(merged) == 0 {
				merged = append(merged, current)
				continue
			}
			last := &merged[len(merged)-1]
			if uint32(current.start) <= uint32(last.end)+1 {
				if current.end > last.end {
					last.end = current.end
				}
				continue
			}
			merged = append(merged, current)
		}
		l.ranges[key] = merged
	}
}

func (l *endpointAllowlist) match(host string, port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	key, _, err := normalizeEndpointHost(host)
	if err != nil {
		return false
	}
	ranges := l.ranges[key]
	target := uint16(port)
	index := sort.Search(len(ranges), func(i int) bool {
		return ranges[i].end >= target
	})
	return index < len(ranges) && ranges[index].start <= target
}

// ============================================================================
//  ACL (访问控制列表) - 顶层结构
// ============================================================================

// ACL 持有已编译的访问控制列表规则。
type ACL struct {
	inboundIPv4          *radixTree
	inboundIPv6          *radixTree
	inboundAllowIPv4     *radixTree
	inboundAllowIPv6     *radixTree
	inboundAllowEnabled  bool
	outboundIPv4         *radixTree
	outboundIPv6         *radixTree
	outbound             *domainMatcher
	outboundAllow        *endpointAllowlist
	outboundAllowEnabled bool
}

// ShouldDeny 检查对于给定的地址和方向，请求是否应该被拒绝。
// 出站 allow_outbound 规则包含端口，必须通过 ShouldDenyOutbound 检查。
func (a *ACL) ShouldDeny(address string, direction string) bool {
	if a == nil {
		return false
	}
	direction = strings.ToLower(direction)
	if direction == "inbound" {
		ip := net.ParseIP(address)
		if ip == nil {
			// 白名单模式必须 fail closed；旧的 deny-only 模式保持兼容。
			return a.inboundAllowEnabled
		}

		var denyAction int
		var allowAction int
		// 检查是否为 IPv4 地址
		if ipv4 := ip.To4(); ipv4 != nil {
			denyAction = a.inboundIPv4.Match(ipv4)
			allowAction = a.inboundAllowIPv4.Match(ipv4)
		} else {
			denyAction = a.inboundIPv6.Match(ip)
			allowAction = a.inboundAllowIPv6.Match(ip)
		}

		// deny_inbound 中的 ! 例外已由 LPM 体现在 denyAction 中。
		if denyAction == ActionDeny {
			return true
		}
		return a.inboundAllowEnabled && allowAction != ActionAllow

	} else if direction == "outbound" {
		// 首先，尝试将地址解析为 IP
		ip := net.ParseIP(address)
		if ip != nil {
			var action int
			if ipv4 := ip.To4(); ipv4 != nil {
				action = a.outboundIPv4.Match(ipv4)
			} else {
				action = a.outboundIPv6.Match(ip)
			}
			return action == ActionDeny
		}

		// 如果不是有效的 IP 地址，则假定为域名并根据域名规则进行检查
		return a.outbound.Match(address)
	}

	return false
}

// ShouldDenyOutbound checks an outbound target using its original host and
// destination port. Effective deny_outbound rules take precedence over the
// allow_outbound whitelist.
func (a *ACL) ShouldDenyOutbound(host string, port int) bool {
	if a == nil {
		return false
	}

	_, normalizedHost, err := normalizeEndpointHost(host)
	if err != nil {
		// Invalid hosts cannot match a whitelist. In legacy deny-only mode the
		// dial/resolve path will report the malformed host as before.
		return a.outboundAllowEnabled
	}
	if a.ShouldDeny(normalizedHost, "outbound") {
		return true
	}
	if !a.outboundAllowEnabled {
		return false
	}
	return !a.outboundAllow.match(normalizedHost, port)
}

// ShouldDenyOutboundAddress is a convenience wrapper for callers that have a
// canonical host:port target, including upstream proxy paths.
func (a *ACL) ShouldDenyOutboundAddress(address string) bool {
	if a == nil {
		return false
	}
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return true
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return true
	}
	return a.ShouldDenyOutbound(host, port)
}

// LoadACL 从给定路径加载并解析 ACL 配置文件。
func LoadACL(path string) (*ACL, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	acl := &ACL{
		inboundIPv4:      newRadixTree(),
		inboundIPv6:      newRadixTree(),
		inboundAllowIPv4: newRadixTree(),
		inboundAllowIPv6: newRadixTree(),
		outboundIPv4:     newRadixTree(),
		outboundIPv6:     newRadixTree(),
		outbound:         newDomainMatcher(),
		outboundAllow:    newEndpointAllowlist(),
	}

	scanner := bufio.NewScanner(file)
	var currentSection string
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		// 跳过空行和注释
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}

		// 解析区域标记
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch currentSection {
			case "allow_inbound":
				acl.inboundAllowEnabled = true
			case "allow_outbound":
				acl.outboundAllowEnabled = true
			}
			continue
		}

		// 检查行是否以 "!" 开头 (例外规则)
		isException := false
		cleanLine := line
		if strings.HasPrefix(line, "!") {
			isException = true
			cleanLine = strings.TrimSpace(line[1:])
		}

		// 确定当前规则的动作
		action := ActionDeny
		if isException {
			action = ActionAllow
		}

		// parseIPNet 是一个辅助函数，用于解析 IP/CIDR
		parseIPNet := func(l string) (*net.IPNet, bool) {
			_, ipNet, err := net.ParseCIDR(l)
			if err == nil {
				return ipNet, true
			}
			ip := net.ParseIP(l)
			if ip == nil {
				return nil, false
			}
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			return &net.IPNet{IP: ip, Mask: mask}, true
		}

		switch currentSection {
		case "deny_inbound":
			if ipNet, ok := parseIPNet(cleanLine); ok {
				if ipv4 := ipNet.IP.To4(); ipv4 != nil {
					ipNet.IP = ipv4
					acl.inboundIPv4.Insert(ipNet, action)
				} else {
					ipNet.IP = ipNet.IP.To16()
					if ipNet.IP != nil {
						acl.inboundIPv6.Insert(ipNet, action)
					}
				}
			}

		case "allow_inbound":
			if isException {
				return nil, fmt.Errorf("%s:%d: allow_inbound does not support ! exception rules", path, lineNumber)
			}
			ipNet, ok := parseIPNet(cleanLine)
			if !ok {
				return nil, fmt.Errorf("%s:%d: allow_inbound requires an IP or CIDR, got %q", path, lineNumber, line)
			}
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				ipNet.IP = ipv4
				acl.inboundAllowIPv4.Insert(ipNet, ActionAllow)
			} else {
				ipNet.IP = ipNet.IP.To16()
				if ipNet.IP == nil {
					return nil, fmt.Errorf("%s:%d: invalid allow_inbound IP %q", path, lineNumber, line)
				}
				acl.inboundAllowIPv6.Insert(ipNet, ActionAllow)
			}

		case "deny_outbound":
			// 尝试将该行解析为 IP/CIDR
			if ipNet, ok := parseIPNet(cleanLine); ok {
				// 如果是 IP 或 CIDR
				if ipv4 := ipNet.IP.To4(); ipv4 != nil {
					ipNet.IP = ipv4
					acl.outboundIPv4.Insert(ipNet, action)
				} else {
					ipNet.IP = ipNet.IP.To16()
					if ipNet.IP != nil {
						acl.outboundIPv6.Insert(ipNet, action)
					}
				}
			} else {
				// 如果不是 IP, 则作为域名处理
				// 注意：域名规则的 "!" 处理在 AddRule 内部或此处传递皆可。
				// 为了保持一致性，我们直接传入原始行 (含 !)，让 AddRule 处理
				acl.outbound.AddRule(line)
			}

		case "allow_outbound":
			if isException {
				return nil, fmt.Errorf("%s:%d: allow_outbound does not support ! exception rules", path, lineNumber)
			}
			key, ports, err := parseOutboundAllowRule(line)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: invalid allow_outbound rule %q: %w", path, lineNumber, line, err)
			}
			acl.outboundAllow.add(key, ports)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	acl.outboundAllow.finalize()
	return acl, nil
}

func ACL_inbound_allow(acl *ACL, remoteAddr net.Addr) bool {
	if acl == nil {
		return true // 没有设置访问控制，默认允许所有连接
	}
	if remoteAddr == nil {
		return !acl.inboundAllowEnabled
	}
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return !acl.inboundAllowEnabled
	}
	return !acl.ShouldDeny(host, "inbound")
}

// ResolveAddrWithACL 解析地址，根据 localIPs 的优先级选择最佳的本地和远程地址对
// localIPs: 本地 IP 列表，索引越小优先级越高
// 返回: (本地地址, 远程地址, 是否被ACL拒绝, 错误)
func ResolveAddrWithACL(ctx context.Context, acl *ACL, network string, localIPs []string, address string) (net.Addr, net.Addr, bool, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid address format: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, nil, false, fmt.Errorf("invalid port %q: must be between 1 and 65535", portStr)
	}

	// 白名单匹配原始请求的 host+port；deny_outbound 仍然优先。
	if acl != nil && acl.ShouldDenyOutbound(host, port) {
		return nil, nil, true, fmt.Errorf("ACL rule denied access to target: %s", address)
	}

	// 1. 获取候选的远程 IP 列表 (remoteCandidates)
	var remoteCandidates []net.IP

	// 尝试直接解析为 IP
	ip := net.ParseIP(host)
	if ip != nil {
		remoteCandidates = []net.IP{ip}
	} else {
		// 确定 DNS 查询的网络类型
		var ipNetwork string
		switch network {
		case "tcp4", "udp4":
			ipNetwork = "ip4"
		case "tcp6", "udp6":
			ipNetwork = "ip6"
		default:
			ipNetwork = "ip"
		}

		// DNS 查询
		ips, err := net.DefaultResolver.LookupIP(ctx, ipNetwork, host)
		if err != nil {
			return nil, nil, false, fmt.Errorf("DNS lookup failed for '%s': %w", host, err)
		}
		if len(ips) == 0 {
			return nil, nil, false, fmt.Errorf("no IP address found for host '%s'", host)
		}
		remoteCandidates = ips
	}

	// 2. 准备本地候选 IP 列表
	// 如果调用者没有提供 localIPs，我们放入一个 nil 值，表示让系统自动选择本地地址
	var localCandidates []*net.UDPAddr
	if len(localIPs) > 0 {
		for _, lIP := range localIPs {
			if lIP == "" {
				continue
			}
			resolvedLocal, err := net.ResolveUDPAddr("udp", net.JoinHostPort(lIP, "0"))
			if err != nil {
				return nil, nil, false, err
			}
			localCandidates = append(localCandidates, resolvedLocal)
		}
	}
	// 如果没有有效的本地指定 IP，加入一个 nil，代表"任意本地地址"
	if len(localCandidates) == 0 {
		localCandidates = []*net.UDPAddr{nil}
	}

	var selectedLocalIP net.IP
	var selectedRemoteIP net.IP
	var denied bool

	// 3. 双重循环匹配：外层 Local (高优)，内层 Remote
	// 逻辑：必须优先使用优先级高的 localIP。
	// 即使 Remote 有多个 IP，只要 Remote 的某个 IP 能配合当前的 Local IP 连通，就立即选中。
	found := false

MatchLoop:
	for _, localAddr := range localCandidates {
		for _, remoteIP := range remoteCandidates {
			// 3.1 协议族检查
			// 如果指定了 localAddr，必须保证协议族一致
			if localAddr != nil && !isFamilyMatch(localAddr.IP, remoteIP) {
				continue
			}

			// 3.2 IP 级 ACL 检查 (Lazy check)
			// 在这里检查是为了如果高优 IP 被封禁，可以回退到下一个 IP
			if acl != nil && acl.ShouldDeny(remoteIP.String(), "outbound") {
				// 记录一下被拒绝，但继续尝试其他组合，
				// 除非遍历完所有组合都失败，否则不立即返回 ACL 错误
				denied = true
				continue
			}

			// 3.3 路由/连通性探测 (使用 UDP Dial 探测)
			// 这一步核心在于验证：内核是否允许从 localAddr 路由到 remoteIP
			probeConn, err := net.DialUDP("udp", localAddr, &net.UDPAddr{IP: remoteIP, Port: port})
			if err == nil {
				// 成功匹配！
				selectedRemoteIP = remoteIP
				// 如果 localAddr 是 nil (未指定)，我们需要获取系统自动分配的 IP
				if localAddr == nil {
					// 通过 LocalAddr() 获取系统选定的出站 IP
					if udpAddr, ok := probeConn.LocalAddr().(*net.UDPAddr); ok {
						selectedLocalIP = udpAddr.IP
					}
				} else {
					selectedLocalIP = localAddr.IP
				}

				probeConn.Close()
				found = true
				break MatchLoop
			}
		}
	}

	if !found {
		if denied {
			return nil, nil, true, fmt.Errorf("ACL rule denied access to IP from %s", host)
		} else {
			return nil, nil, false, fmt.Errorf("no reachable IP address pair found for host '%s' with provided local IPs", host)
		}
	}

	switch network {
	case "tcp", "tcp4", "tcp6":
		return &net.TCPAddr{IP: selectedLocalIP, Port: 0}, &net.TCPAddr{IP: selectedRemoteIP, Port: port}, false, nil
	case "udp", "udp4", "udp6":
		return &net.UDPAddr{IP: selectedLocalIP, Port: 0}, &net.UDPAddr{IP: selectedRemoteIP, Port: port}, false, nil
	default:
		return nil, nil, false, net.UnknownNetworkError(network)
	}
}

// 辅助函数：判断两个 IP 是否协议族匹配
func isFamilyMatch(ip1, ip2 net.IP) bool {
	// 如果任意一个为空，假设不限制或者是 nil
	// 这里假设 localAddr 如果不为 nil 则必须匹配
	if len(ip1) == 0 || len(ip2) == 0 {
		return true
	}

	// To4() 返回非 nil 表示是 IPv4
	v4_1 := ip1.To4() != nil
	v4_2 := ip2.To4() != nil

	return v4_1 == v4_2
}
