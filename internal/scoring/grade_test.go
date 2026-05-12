package scoring

import "testing"

func TestThresholds_Grade_TLS(t *testing.T) {
	cases := []struct {
		score int
		want  Grade
	}{
		{100, GradeAPlus},
		{95, GradeAPlus},
		{94, GradeA},
		{80, GradeA},
		{79, GradeB},
		{65, GradeB},
		{64, GradeC},
		{50, GradeC},
		{49, GradeD},
		{35, GradeD},
		{34, GradeE},
		{20, GradeE},
		{19, GradeF},
		{0, GradeF},
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
		want  Grade
	}{
		{100, GradeAPlus},
		{95, GradeAPlus},
		{94, GradeA},
		{85, GradeA},
		{84, GradeB},
		{70, GradeB},
		{69, GradeC},
		{55, GradeC},
		{40, GradeD},
		{25, GradeE},
		{24, GradeF},
		{0, GradeF},
	}
	for _, c := range cases {
		if got := HeadersThresholds.Grade(c.score); got != c.want {
			t.Errorf("Headers Grade(%d) = %s, want %s", c.score, got, c.want)
		}
	}
}

func TestWorst(t *testing.T) {
	cases := []struct {
		a, b, want Grade
	}{
		{GradeAPlus, GradeA, GradeA},
		{GradeA, GradeAPlus, GradeA},
		{GradeT, GradeF, GradeT},
		{GradeF, GradeT, GradeT},
		{GradeB, GradeB, GradeB},
		{GradeAPlus, GradeT, GradeT},
	}
	for _, c := range cases {
		if got := Worst(c.a, c.b); got != c.want {
			t.Errorf("Worst(%s, %s) = %s, want %s", c.a, c.b, got, c.want)
		}
	}
}

func TestGrade_IsValid(t *testing.T) {
	valid := []Grade{GradeAPlus, GradeA, GradeB, GradeC, GradeD, GradeE, GradeF, GradeT}
	for _, g := range valid {
		if !g.IsValid() {
			t.Errorf("%q should be valid", g)
		}
	}
	for _, g := range []Grade{"", "Z", "A++", "a+"} {
		if g.IsValid() {
			t.Errorf("%q should be invalid", g)
		}
	}
}
