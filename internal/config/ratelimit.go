package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// RateLimit is an "<N>/<unit>" rate expression — e.g. "10/hour", "1/minute".
// Recognised units: second|sec|s, minute|min|m, hour|h, day|d.
type RateLimit struct {
	Count  int
	Period time.Duration
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (r *RateLimit) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := parseRateLimit(s)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

func parseRateLimit(s string) (RateLimit, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "/", 2)
	if len(parts) != 2 {
		return RateLimit{}, fmt.Errorf("invalid rate %q: expected \"<count>/<unit>\"", s)
	}
	count, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || count <= 0 {
		return RateLimit{}, fmt.Errorf("invalid rate count %q: must be a positive integer", parts[0])
	}
	var period time.Duration
	switch strings.ToLower(strings.TrimSpace(parts[1])) {
	case "second", "sec", "s":
		period = time.Second
	case "minute", "min", "m":
		period = time.Minute
	case "hour", "h":
		period = time.Hour
	case "day", "d":
		period = 24 * time.Hour
	default:
		return RateLimit{}, fmt.Errorf("unknown rate period %q (expected second|minute|hour|day)", parts[1])
	}
	return RateLimit{Count: count, Period: period}, nil
}
