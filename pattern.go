package samba

import "strings"

// SMB search patterns.
//
// QUERY_DIRECTORY carries a search pattern that the *server* is expected to
// apply: clients (Windows Explorer, smbclient) send things like `*.txt` and
// show whatever comes back, so a server that only matches the pattern exactly
// answers `STATUS_NO_SUCH_FILE` for every realistic wildcard query.
//
// The dialect here is DOS/Windows wildcarding, which is not quite shell
// globbing:
//
//   - matching is case-insensitive,
//   - `?` matches exactly one character,
//   - `*` matches any run of characters, including none, and — unlike a
//     shell glob — it crosses the `.` separator, so `*.txt` matches `a.txt`
//     and `f1*` matches `f1.txt`,
//   - a trailing `.` is ignored, so `*` and `*.` are equivalent for names
//     without an extension (a DOS leftover that Windows keeps).
//
// Short (8.3) names are not matched because this server never synthesizes them;
// clients that care can see the long name in the directory listing.

// matchPattern reports whether name matches the SMB search pattern pattern.
// Matching is rune-wise and case-insensitive.
func matchPattern(pattern, name string) bool {
	p := []rune(strings.ToLower(pattern))
	n := []rune(strings.ToLower(name))
	// A trailing dot is not significant in DOS wildcards.
	if len(p) > 0 && p[len(p)-1] == '.' {
		p = p[:len(p)-1]
	}

	pi, ni := 0, 0
	star, mark := -1, 0
	for ni < len(n) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == n[ni]):
			pi++
			ni++
		case pi < len(p) && p[pi] == '*':
			star = pi
			mark = ni
			pi++
		case star >= 0:
			// Backtrack: let the last `*` absorb one more character.
			pi = star + 1
			mark++
			ni = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// hasWildcard reports whether a search pattern needs matching rather than a
// plain comparison.
func hasWildcard(pattern string) bool {
	return strings.ContainsAny(pattern, "*?")
}
