package report

import (
	"sort"

	"github.com/Jomar/websec101/internal/checks"
)

// severityPenalty maps severities to score deductions per
// SPECIFICATIONS.md §6.3.
var severityPenalty = map[checks.Severity]int{
	checks.SeverityCritical: 25,
	checks.SeverityHigh:     10,
	checks.SeverityMedium:   5,
	checks.SeverityLow:      2,
	checks.SeverityInfo:     0,
}

// score applies penalties for failing/warning findings. error-status
// findings count as half-penalty (we don't know what would have been).
func score(findings []checks.Finding) int {
	s := 100
	for _, f := range findings {
		p, ok := severityPenalty[f.Severity]
		if !ok {
			continue
		}
		//nolint:exhaustive // intentional partial switch
		switch f.Status {
		case checks.StatusFail:
			s -= p
		case checks.StatusWarn:
			s -= p / 2
		case checks.StatusError:
			s -= p / 2
		}
	}
	if s < 0 {
		s = 0
	}
	if s > 100 {
		s = 100
	}
	return s
}

// letter maps a score to its letter grade.
func letter(s int) string {
	switch {
	case s >= 95:
		return "A+"
	case s >= 85:
		return "A"
	case s >= 75:
		return "B"
	case s >= 65:
		return "C"
	case s >= 50:
		return "D"
	default:
		return "F"
	}
}

// familyWeights are the global-score weighting per SPECIFICATIONS.md §6.3.
// Sum is 100. The "custom" bucket here covers our `http` and `wellknown`
// families, since those map to the spec's Custom domain.
var familyWeights = map[checks.Family]int{
	checks.FamilyTLS:       25,
	checks.FamilyHeaders:   25,
	checks.FamilyDNS:       20,
	checks.FamilyEmail:     15,
	checks.FamilyCookies:   10,
	checks.FamilyHTTP:      3, // sum of "custom" with WellKnown below = 5
	checks.FamilyWellKnown: 2,
}

// computeSummary computes the global Counts + Score + Grade + per-family
// scores. scoreInputs is the subset of findings (fail/warn/error) that
// affects scoring; findings is the full set used for counts.
func computeSummary(findings []checks.Finding, scoreInputs []checks.Finding) Summary {
	s := Summary{ScoresPerFamily: map[string]int{}}

	// Counts (across the entire result set).
	for _, f := range findings {
		//nolint:exhaustive // intentional partial switch
		switch f.Status {
		case checks.StatusPass:
			s.Counts.Passed++
		case checks.StatusSkipped:
			s.Counts.Skipped++
		case checks.StatusError:
			s.Counts.Errored++
		case checks.StatusFail, checks.StatusWarn:
			//nolint:exhaustive // intentional partial switch
			switch f.Severity {
			case checks.SeverityCritical:
				s.Counts.Critical++
			case checks.SeverityHigh:
				s.Counts.High++
			case checks.SeverityMedium:
				s.Counts.Medium++
			case checks.SeverityLow:
				s.Counts.Low++
			case checks.SeverityInfo:
				s.Counts.Info++
			}
		}
	}

	// Per-family score: each family is graded only on its own
	// fail/warn/error findings (passes contribute implicitly because
	// the baseline is 100).
	byFamily := map[checks.Family][]checks.Finding{}
	for _, f := range scoreInputs {
		byFamily[f.Family] = append(byFamily[f.Family], f)
	}
	for fam, items := range byFamily {
		s.ScoresPerFamily[string(fam)] = score(items)
	}
	// Make sure every family that had any finding (even just passes) is
	// represented at 100 if no negatives.
	for _, f := range findings {
		key := string(f.Family)
		if _, ok := s.ScoresPerFamily[key]; !ok {
			s.ScoresPerFamily[key] = 100
		}
	}

	// Global weighted score using familyWeights — only families that
	// produced findings count, and the weights are renormalised across
	// participating families.
	totalWeight := 0
	for fam := range byFamilyCounts(findings) {
		if w, ok := familyWeights[fam]; ok {
			totalWeight += w
		}
	}
	weighted := 0
	if totalWeight > 0 {
		for fam, fs := range byFamilyCounts(findings) {
			w, ok := familyWeights[fam]
			if !ok {
				continue
			}
			famScore := score(filterFamilyNegatives(fs))
			weighted += famScore * w
		}
		s.Score = weighted / totalWeight
	} else {
		s.Score = score(scoreInputs)
	}
	s.Grade = letter(s.Score)

	// Quick-wins: stable sort by severity desc, then ID.
	for _, f := range findings {
		if isQuickWin(f) {
			s.QuickWins = append(s.QuickWins, f.ID)
		}
	}
	sort.SliceStable(s.QuickWins, func(i, j int) bool {
		return s.QuickWins[i] < s.QuickWins[j]
	})

	return s
}

func byFamilyCounts(findings []checks.Finding) map[checks.Family][]checks.Finding {
	out := map[checks.Family][]checks.Finding{}
	for _, f := range findings {
		out[f.Family] = append(out[f.Family], f)
	}
	return out
}

func filterFamilyNegatives(fs []checks.Finding) []checks.Finding {
	out := fs[:0:0]
	for _, f := range fs {
		//nolint:exhaustive // intentional partial switch
		switch f.Status {
		case checks.StatusFail, checks.StatusWarn, checks.StatusError:
			out = append(out, f)
		}
	}
	return out
}
