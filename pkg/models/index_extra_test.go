package models

import (
	"reflect"
	"testing"
)

func TestAddRulePreservesAndMergesImplementations(t *testing.T) {
	index := &PolicyIndex{Rules: map[string]*Rule{}, Packs: map[string]*Pack{}}
	original := &Rule{ID: "rule:aliyun:example", IaCTypes: []string{"ros", "terraform"}, ResourceTypes: []string{"ALIYUN::ECS::Instance"}, FilePath: "fallback.rego", Content: "fallback", Implementations: map[string]*RuleImpl{"ros": {FilePath: "ros.rego", Content: "ros"}, "terraform": {FilePath: "tf.rego", Content: "terraform"}}}
	index.AddRule(original)
	got := index.Rules[original.ID]
	if got.Implementations["ros"].Content != "ros" || got.Implementations["terraform"].Content != "terraform" {
		t.Fatalf("original implementations lost: %+v", got.Implementations)
	}
	incoming := &Rule{ID: original.ID, IaCTypes: []string{"ros", "other"}, ResourceTypes: []string{"ALIYUN::ECS::Instance", "Other"}, FilePath: "incoming.rego", Content: "incoming", Implementations: map[string]*RuleImpl{"ros": {FilePath: "updated.rego", Content: "updated"}}}
	index.AddRule(incoming)
	if len(index.RuleList) != 1 || !reflect.DeepEqual(got.IaCTypes, []string{"ros", "terraform", "other"}) || !reflect.DeepEqual(got.ResourceTypes, []string{"ALIYUN::ECS::Instance", "Other"}) {
		t.Fatalf("merge=%+v", got)
	}
	if got.Implementations["ros"].Content != "updated" || got.Implementations["terraform"].Content != "terraform" || got.Implementations["other"].Content != "incoming" {
		t.Fatalf("merged implementations: %+v", got.Implementations)
	}
}
