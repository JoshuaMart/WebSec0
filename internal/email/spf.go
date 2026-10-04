package email

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/JoshuaMart/websec0/internal/scan"
)

var (
	modifierName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]*$`)
	topLabel     = regexp.MustCompile(`^([a-zA-Z0-9]*[a-zA-Z][a-zA-Z0-9]*|[a-zA-Z0-9]+-[a-zA-Z0-9-]*[a-zA-Z0-9])$`)
)

const permissivePrefixWarning = "A positive /0 IP mechanism authorizes any sender of that address family that reaches it."

func inspectSPF(domain string, lookup lookupFunc) scan.SPFReport {
	out := scan.SPFReport{DNSRecord: newRecord("email.spf"), Includes: []string{}}
	records, err := lookup(domain)
	if err != nil {
		unavailable(&out.DNSRecord, domain)
		return out
	}
	for _, record := range records {
		version, _, _ := strings.Cut(record, " ")
		if strings.EqualFold(version, "v=spf1") {
			out.Records = append(out.Records, record)
		}
	}
	if len(out.Records) == 0 {
		return out
	}
	if len(out.Records) != 1 {
		out.State = scan.DNSRecordInvalid
		out.Warnings = append(out.Warnings, "Multiple SPF records are published; SPF requires exactly one policy record.")
		return out
	}
	out.State = scan.DNSRecordObserved
	if !parseSPF(out.Records[0], &out) {
		out.State = scan.DNSRecordInvalid
		out.All, out.Redirect, out.Includes = "", "", []string{}
		out.Warnings = append(out.Warnings, "The SPF record contains an invalid mechanism, modifier or IP range.")
		return out
	}
	if out.All == "+all" {
		out.Warnings = append(out.Warnings, "The +all mechanism authorizes any sender that reaches it.")
	}
	if out.All != "" && out.Redirect != "" {
		out.Warnings = append(out.Warnings, "The redirect modifier is ignored because an all mechanism is present.")
	}
	return out
}

// parseSPF checks mechanism structure and literal IP ranges. Domain-spec macros
// and dependency policies need an actual sender context and are not evaluated.
func parseSPF(record string, out *scan.SPFReport) bool {
	for _, c := range record {
		if c < 32 || c > 126 {
			return false
		}
	}
	modifiers := map[string]bool{}
	var hasPTR bool
	for _, term := range strings.Split(record, " ")[1:] {
		if term == "" {
			continue
		}
		if i := strings.IndexAny(term, "=:/"); i >= 0 && term[i] == '=' {
			name, value := term[:i], term[i+1:]
			if !modifierName.MatchString(name) || macroStringEnd(value) < 0 {
				return false
			}
			name = strings.ToLower(name)
			if name == "redirect" || name == "exp" {
				if modifiers[name] || !domainSpec(value) {
					return false
				}
				modifiers[name] = true
				if name == "redirect" {
					out.Redirect = value
				}
			}
			continue // Unknown modifiers are ignored by SPF implementations.
		}
		qualifier := "+"
		if strings.ContainsAny(term[:1], "+-~?") {
			qualifier, term = term[:1], term[1:]
		}
		if term == "" {
			return false
		}
		i := strings.IndexAny(term, ":/")
		name, arg := term, ""
		if i >= 0 {
			name, arg = term[:i], term[i:]
		}
		switch strings.ToLower(name) {
		case "all":
			if arg != "" {
				return false
			}
			if out.All == "" {
				out.All = qualifier + "all"
			}
		case "include", "exists":
			if !strings.HasPrefix(arg, ":") || !domainSpec(arg[1:]) {
				return false
			}
			if strings.EqualFold(name, "include") {
				out.Includes = append(out.Includes, arg[1:])
			}
		case "ip4", "ip6":
			if !strings.HasPrefix(arg, ":") {
				return false
			}
			value := arg[1:]
			addr, err := netip.ParseAddr(value)
			var universal bool
			if strings.Contains(value, "/") {
				prefix, prefixErr := netip.ParsePrefix(value)
				addr, err = prefix.Addr(), prefixErr
				universal = prefix.Bits() == 0
			}
			if err != nil || addr.Zone() != "" || (strings.EqualFold(name, "ip4") != addr.Is4()) {
				return false
			}
			if universal && qualifier == "+" && out.All == "" {
				out.Warnings = appendUnique(out.Warnings, permissivePrefixWarning)
			}
		case "a", "mx":
			if !addressMechanism(arg) {
				return false
			}
		case "ptr":
			if arg != "" && (!strings.HasPrefix(arg, ":") || !domainSpec(arg[1:])) {
				return false
			}
			hasPTR = true
		default:
			return false
		}
	}
	if hasPTR {
		out.Warnings = append(out.Warnings, "The ptr mechanism is discouraged by the SPF specification.")
	}
	return true
}

func addressMechanism(arg string) bool {
	if strings.HasPrefix(arg, ":") {
		arg = arg[1:]
		var domain string
		if i := cidrStart(arg); i >= 0 {
			domain, arg = arg[:i], arg[i:]
		} else {
			domain, arg = arg, ""
		}
		if !domainSpec(domain) {
			return false
		}
	}
	if arg == "" {
		return true
	}
	if !strings.HasPrefix(arg, "/") {
		return false
	}
	v4, v6, dual := strings.Cut(arg[1:], "//")
	if strings.HasPrefix(arg, "//") {
		v4, v6, dual = "", arg[2:], true
	}
	if v4 != "" && !cidr(v4, 32) {
		return false
	}
	if dual {
		return cidr(v6, 128)
	}
	return v4 != ""
}

func cidr(value string, maxBits int) bool {
	if value == "" || len(value) > 3 || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(value)
	return err == nil && n <= maxBits
}

func domainSpec(value string) bool {
	lastMacro := macroStringEnd(value)
	if value == "" || lastMacro < 0 {
		return false
	}
	// RFC 7208 domain-end is a macro expansion or a dot and a top label.
	if lastMacro == len(value) {
		return true
	}
	value = strings.TrimSuffix(value, ".")
	i := strings.LastIndexByte(value, '.')
	return i >= 0 && topLabel.MatchString(value[i+1:])
}

// cidrStart ignores slashes used as delimiters inside SPF macros.
func cidrStart(value string) int {
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+1 < len(value) {
			i++
			if value[i] == '{' {
				end := strings.IndexByte(value[i:], '}')
				if end < 0 {
					return -1
				}
				i += end
			}
		} else if value[i] == '/' {
			return i
		}
	}
	return -1
}

// macroStringEnd validates macro syntax and returns the end of the last expansion,
// or -1 for invalid input. Zero means the string contains only literals.
func macroStringEnd(value string) int {
	lastEnd := 0
	for i := 0; i < len(value); i++ {
		if value[i] < 33 || value[i] > 126 {
			return -1
		}
		if value[i] != '%' {
			continue
		}
		i++
		if i == len(value) {
			return -1
		}
		switch value[i] {
		case '%', '_', '-':
		case '{':
			i++
			if i == len(value) || !strings.ContainsRune("slodipvhSLODIPVH", rune(value[i])) {
				return -1
			}
			i++
			for i < len(value) && value[i] >= '0' && value[i] <= '9' {
				i++
			}
			if i < len(value) && (value[i] == 'r' || value[i] == 'R') {
				i++
			}
			for i < len(value) && strings.ContainsRune(".-+,/_=", rune(value[i])) {
				i++
			}
			if i == len(value) || value[i] != '}' {
				return -1
			}
		default:
			return -1
		}
		lastEnd = i + 1
	}
	return lastEnd
}
