package build

// Logger receives progress and diagnostic messages emitted by the build pipeline.
// It is injected through Load; the package holds no global logging state.
type Logger interface {
	Info(format string, args ...any)
	Success(format string, args ...any)
	Warn(format string, args ...any)
	Step(format string, args ...any)
}

// NopLogger discards all messages. Intended for tests and silent tooling.
type NopLogger struct{}

func (NopLogger) Info(string, ...any)    {}
func (NopLogger) Success(string, ...any) {}
func (NopLogger) Warn(string, ...any)    {}
func (NopLogger) Step(string, ...any)    {}
