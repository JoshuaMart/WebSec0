// Package scoring contains grade types and threshold tables shared by the
// TLS and HTTP header scoring engines.
package scoring

// Grade is the canonical letter grade returned in API responses.
// The ordering, from best to worst, is: A+ A B C D E F T.
// GradeT ("no trust") is reserved for cases where certificate validation
// fails — it is considered the worst outcome.
type Grade string

const (
	GradeAPlus Grade = "A+"
	GradeA     Grade = "A"
	GradeB     Grade = "B"
	GradeC     Grade = "C"
	GradeD     Grade = "D"
	GradeE     Grade = "E"
	GradeF     Grade = "F"
	GradeT     Grade = "T"
)

// IsValid reports whether g is one of the known grades.
func (g Grade) IsValid() bool {
	switch g {
	case GradeAPlus, GradeA, GradeB, GradeC, GradeD, GradeE, GradeF, GradeT:
		return true
	}
	return false
}

// Thresholds defines the inclusive lower bound for each non-F grade.
// A score below E maps to F.
type Thresholds struct {
	APlus int
	A     int
	B     int
	C     int
	D     int
	E     int
}

// Grade returns the grade letter for the given score under these thresholds.
func (t Thresholds) Grade(score int) Grade {
	switch {
	case score >= t.APlus:
		return GradeAPlus
	case score >= t.A:
		return GradeA
	case score >= t.B:
		return GradeB
	case score >= t.C:
		return GradeC
	case score >= t.D:
		return GradeD
	case score >= t.E:
		return GradeE
	default:
		return GradeF
	}
}

// TLSThresholds follows SPEC §5.1.
var TLSThresholds = Thresholds{APlus: 95, A: 80, B: 65, C: 50, D: 35, E: 20}

// HeadersThresholds follows SPEC §4.2.
var HeadersThresholds = Thresholds{APlus: 95, A: 85, B: 70, C: 55, D: 40, E: 25}

// Worst returns the worse of two grades. GradeT outranks F (it represents a
// trust failure, not merely a low score).
func Worst(a, b Grade) Grade {
	if rank(a) < rank(b) {
		return a
	}
	return b
}

func rank(g Grade) int {
	switch g {
	case GradeAPlus:
		return 8
	case GradeA:
		return 7
	case GradeB:
		return 6
	case GradeC:
		return 5
	case GradeD:
		return 4
	case GradeE:
		return 3
	case GradeF:
		return 2
	case GradeT:
		return 1
	default:
		return 0
	}
}
