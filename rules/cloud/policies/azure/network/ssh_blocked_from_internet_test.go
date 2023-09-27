package network

import (
	"testing"

	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"

	"github.com/wuwwlwwl/defsec/pkg/state"

	"github.com/wuwwlwwl/defsec/pkg/providers/azure/network"
	"github.com/wuwwlwwl/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSshBlockedFromInternet(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Security group rule allowing SSH access from the public internet",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Allow:    defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
								Outbound: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Start:    22,
										End:      22,
									},
								},
								SourceAddresses: []defsecTypes.StringValue{
									defsecTypes.String("*", defsecTypes.NewTestMetadata()),
								},
								Protocol: defsecTypes.String("Tcp", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group rule allowing SSH only ICMP",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Allow:    defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
								Outbound: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Start:    22,
										End:      22,
									},
								},
								SourceAddresses: []defsecTypes.StringValue{
									defsecTypes.String("*", defsecTypes.NewTestMetadata()),
								},
								Protocol: defsecTypes.String("Icmp", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule allowing SSH access from a specific address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Allow:    defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
								Outbound: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: defsecTypes.NewTestMetadata(),
										Start:    22,
										End:      22,
									},
								},
								SourceAddresses: []defsecTypes.StringValue{
									defsecTypes.String("82.102.23.23", defsecTypes.NewTestMetadata()),
								},
								Protocol: defsecTypes.String("Tcp", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.Network = test.input
			results := CheckSshBlockedFromInternet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSshBlockedFromInternet.Rule().LongID() {
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
