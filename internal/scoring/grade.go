// Package scoring contains the threshold tables and computation rules that
// turn observation reports into a 0–100 score and a [scan.Grade] letter.
// The Grade type itself lives in internal/scan so this package can import
// scan without creating a cycle.
package scoring

import "github.com/JoshuaMart/websec0/internal/scan"

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
func (t Thresholds) Grade(score int) scan.Grade {
	switch {
	case score >= t.APlus:
		return scan.GradeAPlus
	case score >= t.A:
		return scan.GradeA
	case score >= t.B:
		return scan.GradeB
	case score >= t.C:
		return scan.GradeC
	case score >= t.D:
		return scan.GradeD
	case score >= t.E:
		return scan.GradeE
	default:
		return scan.GradeF
	}
}

// TLSThresholds follows
var TLSThresholds = Thresholds{APlus: 95, A: 80, B: 65, C: 50, D: 35, E: 20}

// HeadersThresholds follows
var HeadersThresholds = Thresholds{APlus: 95, A: 85, B: 70, C: 55, D: 40, E: 25}

// Worst returns the worse of two grades. GradeT outranks F (it represents
// a trust failure, not merely a low score).
func Worst(a, b scan.Grade) scan.Grade {
	if rank(a) < rank(b) {
		return a
	}
	return b
}

func rank(g scan.Grade) int {
	switch g {
	case scan.GradeAPlus:
		return 8
	case scan.GradeA:
		return 7
	case scan.GradeB:
		return 6
	case scan.GradeC:
		return 5
	case scan.GradeD:
		return 4
	case scan.GradeE:
		return 3
	case scan.GradeF:
		return 2
	case scan.GradeT:
		return 1
	default:
		return 0
	}
}
