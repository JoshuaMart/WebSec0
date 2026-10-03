// Package logsafe normalizes external values before they reach log handlers.
package logsafe

import "strings"

// SingleLine preserves line breaks as visible escapes instead of log separators.
func SingleLine(value string) string {
	value = strings.ReplaceAll(value, "\r", `\r`)
	return strings.ReplaceAll(value, "\n", `\n`)
}
