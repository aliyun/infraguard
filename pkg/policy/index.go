package policy

//go:generate go run ../../cmd/policy-gen/main.go

import (
	"github.com/aliyun/infraguard/pkg/models"
)

// EmbeddedIndex is a pre-computed index of all embedded policies.
// It is populated by the generated code in index_gen.go.
var EmbeddedIndex *models.PolicyIndex
