package scan

// Grade is the canonical letter grade emitted in API payloads. The ordering,
// from best to worst, is: A+ A B C D E F T. GradeT ("no trust") is reserved
// for certificate-validation failures and is considered the worst outcome.
//
// The threshold tables that map a 0–100 score to a grade live in the
// internal/scoring package — Grade itself is just the payload-shape enum
// so this package has no upward dependency.
type Grade string

// Grade values.
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
