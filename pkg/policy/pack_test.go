package policy

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestParsePackInCategoryDirectory(t *testing.T) {
	Convey("Given a pack file in an organizational category directory", t, func() {
		content := `package infraguard.packs.aliyun.best_practice

import rego.v1

pack_meta := {
	"id": "best-practice",
	"name": {"en": "Best Practice"},
	"description": {"en": "Best practice checks"},
	"rules": ["ecs-instance-name-required"],
}
`

		pack, err := ParsePackFromContentWithPath(
			content,
			"policies/aliyun/packs/best-practice/best-practice-pack.rego",
			"policies/aliyun/packs",
		)

		Convey("It should keep pack and rule IDs scoped to the provider", func() {
			So(err, ShouldBeNil)
			So(pack, ShouldNotBeNil)
			So(pack.ID, ShouldEqual, "pack:aliyun:best-practice")
			So(pack.RuleIDs, ShouldResemble, []string{"rule:aliyun:ecs-instance-name-required"})
		})
	})
}
