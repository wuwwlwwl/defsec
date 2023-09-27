package options

import (
	"github.com/wuwwlwwl/defsec/pkg/concurrency"
	"github.com/wuwwlwwl/defsec/pkg/debug"
	"github.com/wuwwlwwl/defsec/pkg/progress"
)

type Options struct {
	ProgressTracker     progress.Tracker
	Region              string
	Endpoint            string
	Services            []string
	DebugWriter         debug.Logger
	ConcurrencyStrategy concurrency.Strategy
}
