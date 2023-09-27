package cloudtrail

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/aws/cloudtrail"
	"github.com/wuwwlwwl/defsec/pkg/providers/aws/s3"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckBucketAccessLoggingRequired(t *testing.T) {
	tests := []struct {
		name     string
		inputCT  cloudtrail.CloudTrail
		inputS3  s3.S3
		expected bool
	}{
		{
			name: "Trail has bucket with logging enabled",
			inputCT: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:   defsecTypes.NewTestMetadata(),
						BucketName: defsecTypes.String("my-bucket", defsecTypes.NewTestMetadata()),
					},
				},
			},
			inputS3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("my-bucket", defsecTypes.NewTestMetadata()),
						Logging: s3.Logging{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Trail has bucket without logging enabled",
			inputCT: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:   defsecTypes.NewTestMetadata(),
						BucketName: defsecTypes.String("my-bucket", defsecTypes.NewTestMetadata()),
					},
				},
			},
			inputS3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("my-bucket", defsecTypes.NewTestMetadata()),
						Logging: s3.Logging{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudTrail = test.inputCT
			testState.AWS.S3 = test.inputS3
			results := checkBucketAccessLoggingRequired.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkBucketAccessLoggingRequired.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
