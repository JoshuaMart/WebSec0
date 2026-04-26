package memory

import "errors"

// errInvalidScan is returned when Put receives a nil/empty scan or when the
// underlying cache yields a value of an unexpected type (should never happen
// in practice, but we keep the interface honest).
var errInvalidScan = errors.New("memory: invalid scan")
