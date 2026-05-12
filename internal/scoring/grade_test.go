package scoring

import (
	"testing"

	"github.com/JoshuaMart/websec0/internal/scan"
)

func TestThresholds_Grade_TLS(t *testing.T) {
	cases := []struct {
		score int
		want  scan.Grade
	}{
		{100, scan.GradeAPlus},
		{95, scan.GradeAPlus},
		{94, scan.GradeA},
		{80, scan.GradeA},
		{79, scan.GradeB},
		{65, scan.GradeB},
		{64, scan.GradeC},
		{50, scan.GradeC},
		{49, scan.GradeD},
		{35, scan.GradeD},
		{34, scan.GradeE},
		{20, scan.GradeE},
		{19, scan.GradeF},
		{0, scan.GradeF},
	}
	for _, c := range cases {
		if got := TLSThresholds.Grade(c.score); got != c.want {
			t.Errorf("TLS Grade(%d) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestThresholds_Grade_Headers(t *testing.T) {
	cases := []struct {
		score int
		want  scan.Grade
	}{
		{100, scan.GradeAPlus},
		{95, scan.GradeAPlus},
		{94, scan.GradeA},
		{85, scan.GradeA},
		{84, scan.GradeB},
		{70, scan.GradeB},
		{69, scan.GradeC},
		{55, scan.GradeC},
		{40, scan.GradeD},
		{25, scan.GradeE},
		{24, scan.GradeF},
		{0, scan.GradeF},
	}
	for _, c := range cases {
		if got := HeadersThresholds.Grade(c.score); got != c.want {
			t.Errorf("Headers Grade(%d) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestWorst(t *testing.T) {
	cases := []struct {
		a, b, want scan.Grade
	}{
		{scan.GradeAPlus, scan.GradeA, scan.GradeA},
		{scan.GradeA, scan.GradeAPlus, scan.GradeA},
		{scan.GradeT, scan.GradeF, scan.GradeT},
		{scan.GradeF, scan.GradeT, scan.GradeT},
		{scan.GradeB, scan.GradeB, scan.GradeB},
		{scan.GradeAPlus, scan.GradeT, scan.GradeT},
	}
	for _, c := range cases {
		if got := Worst(c.a, c.b); got != c.want {
			t.Errorf("Worst(%s, %s) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestGrade_IsValid(t *testing.T) {
	valid := []scan.Grade{
		scan.GradeAPlus, scan.GradeA, scan.GradeB, scan.GradeC,
		scan.GradeD, scan.GradeE, scan.GradeF, scan.GradeT,
	}
	for _, g := range valid {
		if !g.IsValid() {
			t.Errorf("%q should be valid", g)
		}
	}
	for _, g := range []scan.Grade{"", "Z", "A++", "a+"} {
		if g.IsValid() {
			t.Errorf("%q should be invalid", g)
		}
	}
}
