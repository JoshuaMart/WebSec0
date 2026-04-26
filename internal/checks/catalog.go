package checks

// Catalog returns the static metadata for every registered Check. The
// HTTP layer renders the result as JSON on GET /api/v1/checks.
//
// Checks may optionally implement Describer to enrich the catalog entry.
// When they don't, only the four interface-mandated fields are populated.
func (r *Registry) Catalog() []CheckMeta {
	all := r.All()
	out := make([]CheckMeta, 0, len(all))
	for _, c := range all {
		m := CheckMeta{
			ID:              c.ID(),
			Family:          c.Family(),
			DefaultSeverity: c.DefaultSeverity(),
		}
		if d, ok := c.(Describer); ok {
			m.Title = d.Title()
			m.Description = d.Description()
			m.RFCRefs = d.RFCRefs()
		}
		out = append(out, m)
	}
	return out
}

// Describer is an optional interface that checks can implement to enrich
// their catalog entry with human-facing documentation.
type Describer interface {
	Title() string
	Description() string
	RFCRefs() []string
}
