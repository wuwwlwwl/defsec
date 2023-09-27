package iam

import (
	"github.com/wuwwlwwl/defsec/pkg/providers/google/iam"
	"github.com/wuwwlwwl/defsec/pkg/terraform"
	defsecTypes "github.com/wuwwlwwl/defsec/pkg/types"
)

func ParsePolicyBlock(block *terraform.Block) []iam.Binding {
	var bindings []iam.Binding
	for _, bindingBlock := range block.GetBlocks("binding") {
		binding := iam.Binding{
			Metadata:                      bindingBlock.GetMetadata(),
			Members:                       nil,
			Role:                          bindingBlock.GetAttribute("role").AsStringValueOrDefault("", bindingBlock),
			IncludesDefaultServiceAccount: defsecTypes.BoolDefault(false, bindingBlock.GetMetadata()),
		}
		membersAttr := bindingBlock.GetAttribute("members")
		members := membersAttr.AsStringValues().AsStrings()
		for _, member := range members {
			binding.Members = append(binding.Members, defsecTypes.String(member, membersAttr.GetMetadata()))
		}
		bindings = append(bindings, binding)
	}
	return bindings
}
