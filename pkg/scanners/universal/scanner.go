package universal

import (
	"context"
	"io/fs"

	"github.com/wuwwlwwl/defsec/pkg/scanners/azure/arm"
	"github.com/wuwwlwwl/defsec/pkg/scanners/cloud/aws"
	"github.com/wuwwlwwl/defsec/pkg/scanners/helm"
	"github.com/wuwwlwwl/defsec/pkg/scanners/options"
	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/scanners/json"
	"github.com/wuwwlwwl/defsec/pkg/scanners/toml"
	"github.com/wuwwlwwl/defsec/pkg/scanners/yaml"

	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/wuwwlwwl/defsec/pkg/scanners"
	"github.com/wuwwlwwl/defsec/pkg/scanners/cloudformation"
	"github.com/wuwwlwwl/defsec/pkg/scanners/dockerfile"
	"github.com/wuwwlwwl/defsec/pkg/scanners/kubernetes"
	"github.com/wuwwlwwl/defsec/pkg/scanners/terraform"
)

type nestableFSScanners interface {
	scanners.FSScanner
	options.ConfigurableScanner
}

type nestableAPIScanners interface {
	scanners.APIScanner
	options.ConfigurableScanner
}

var _ scanners.FSScanner = (*Scanner)(nil)

type Scanner struct {
	fsScanners  []nestableFSScanners
	apiScanners []nestableAPIScanners
}

func New(opts ...options.ScannerOption) *Scanner {
	s := &Scanner{
		fsScanners: []nestableFSScanners{
			terraform.New(opts...),
			cloudformation.New(opts...),
			dockerfile.NewScanner(opts...),
			kubernetes.NewScanner(opts...),
			json.NewScanner(opts...),
			yaml.NewScanner(opts...),
			toml.NewScanner(opts...),
			helm.New(opts...),
			arm.New(opts...),
		},
		apiScanners: []nestableAPIScanners{
			aws.New(opts...),
		},
	}
	return s
}

func (s *Scanner) Name() string {
	return "Universal"
}

func (s *Scanner) ScanFS(ctx context.Context, fs fs.FS, dir string) (scan.Results, error) {
	var results scan.Results
	for _, inner := range s.fsScanners {
		innerResults, err := inner.ScanFS(ctx, fs, dir)
		if err != nil {
			return nil, err
		}
		results = append(results, innerResults...)
	}
	return results, nil
}

func (s *Scanner) Scan(ctx context.Context, cloud *state.State) (scan.Results, error) {
	var results scan.Results

	for _, inner := range s.apiScanners {
		innerResults, err := inner.Scan(ctx, cloud)
		if err != nil {
			return nil, err
		}
		results = append(results, innerResults...)
	}
	return results, nil
}
