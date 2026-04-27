package http

import "github.com/JoshuaMart/websec0/internal/checks"

// Register adds every Web/Custom check to r.
func Register(r *checks.Registry) {
	r.Register(http2MissingCheck{})
	r.Register(http3MissingCheck{})
	r.Register(mixedContentCheck{})
	r.Register(optionsCheck{})
	r.Register(traceCheck{})
	r.Register(corsWildcardCredCheck{})
	r.Register(corsReflectedCheck{})
	r.Register(corsNullCheck{})
	r.Register(stackTraceCheck{})
	r.Register(defaultErrorPageCheck{})
	r.Register(compressionCheck{})
	r.Register(robotsCheck{})
	r.Register(changePasswordCheck{})
	r.Register(sriCheck{})
}
