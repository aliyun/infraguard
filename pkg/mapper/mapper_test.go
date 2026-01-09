package mapper

import (
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	. "github.com/smartystreets/goconvey/convey"
	"gopkg.in/yaml.v3"
)

func TestMapViolations(t *testing.T) {
	Convey("Given the MapViolations function", t, func() {
		Convey("When mapping violations with valid YAML node", func() {
			yamlContent := `Resources:
  WebServer:
    Type: ALIYUN::ECS::InstanceGroup
    Properties:
      AllocatePublicIP: true
`

			var node yaml.Node
			err := yaml.Unmarshal([]byte(yamlContent), &node)
			So(err, ShouldBeNil)

			violations := []models.OPAViolation{
				{
					ID:            "TEST-001",
					ResourceID:    "WebServer",
					ViolationPath: []interface{}{"Resources", "WebServer", "Properties", "AllocatePublicIP"},
					Meta: models.ViolationMeta{
						Severity:       "High",
						Reason:         "Test reason",
						Recommendation: "Test recommendation",
					},
				},
			}

			rich := MapViolations(violations, &node, "test.yaml")

			Convey("It should return 1 violation", func() {
				So(len(rich), ShouldEqual, 1)
			})

			Convey("It should map fields correctly", func() {
				v := rich[0]
				So(v.ID, ShouldEqual, "TEST-001")
				So(v.ResourceID, ShouldEqual, "WebServer")
				So(v.File, ShouldEqual, "test.yaml")
			})

			Convey("It should find the line number", func() {
				So(rich[0].Line, ShouldBeGreaterThan, 0)
			})
		})

		Convey("When mapping violations with nil YAML node", func() {
			violations := []models.OPAViolation{
				{
					ID:            "TEST-003",
					ResourceID:    "Resource",
					ViolationPath: []interface{}{"path"},
					Meta: models.ViolationMeta{
						Severity: "Low",
						Reason:   "Reason",
					},
				},
			}

			rich := MapViolations(violations, nil, "test.yaml")

			Convey("It should return 1 violation", func() {
				So(len(rich), ShouldEqual, 1)
			})

			Convey("It should default to line 1", func() {
				So(rich[0].Line, ShouldEqual, 1)
			})
		})
	})
}

func TestMapViolationsWithLang(t *testing.T) {
	Convey("Given the MapViolationsWithLang function", t, func() {
		yamlContent := `Resources:
  Server:
    Properties:
      Public: true
`

		var node yaml.Node
		err := yaml.Unmarshal([]byte(yamlContent), &node)
		So(err, ShouldBeNil)

		violations := []models.OPAViolation{
			{
				ID:            "TEST-002",
				ResourceID:    "Server",
				ViolationPath: []interface{}{"Resources", "Server", "Properties", "Public"},
				Meta: models.ViolationMeta{
					Severity: "Medium",
					Reason: map[string]interface{}{
						"en": "English reason",
						"zh": "中文原因",
					},
					Recommendation: "Fix it",
				},
			},
		}

		Convey("When language is Chinese", func() {
			rich := MapViolationsWithLang(violations, &node, "test.yaml", "zh")

			Convey("It should return Chinese reason", func() {
				So(len(rich), ShouldEqual, 1)
				So(rich[0].Reason, ShouldEqual, "中文原因")
			})
		})

		Convey("When language is English", func() {
			rich := MapViolationsWithLang(violations, &node, "test.yaml", "en")

			Convey("It should return English reason", func() {
				So(rich[0].Reason, ShouldEqual, "English reason")
			})
		})
	})
}

func TestPathToStrings(t *testing.T) {
	Convey("Given the pathToStrings function", t, func() {
		Convey("When path contains mixed types", func() {
			path := []interface{}{"Resources", "WebServer", 0, "Properties"}
			result := pathToStrings(path)

			Convey("It should convert all elements to strings", func() {
				expected := []string{"Resources", "WebServer", "0", "Properties"}
				So(len(result), ShouldEqual, len(expected))
				for i, e := range expected {
					So(result[i], ShouldEqual, e)
				}
			})
		})
	})
}

func TestFindNode(t *testing.T) {
	Convey("Given the findNode function", t, func() {
		Convey("When traversing a map", func() {
			yamlContent := `Resources:
  MyResource:
    Properties:
      Name: test
`

			var node yaml.Node
			err := yaml.Unmarshal([]byte(yamlContent), &node)
			So(err, ShouldBeNil)

			path := []interface{}{"Resources", "MyResource", "Properties", "Name"}
			line, snippet, _ := findNode(&node, path, "")

			Convey("It should find the correct line", func() {
				So(line, ShouldBeGreaterThan, 0)
				So(line, ShouldEqual, 4)
			})

			_ = snippet
		})

		Convey("When path does not fully exist", func() {
			yamlContent := `Resources:
  MyResource:
    Type: ALIYUN::ECS::InstanceGroup
`

			var node yaml.Node
			err := yaml.Unmarshal([]byte(yamlContent), &node)
			So(err, ShouldBeNil)

			path := []interface{}{"Resources", "MyResource", "Properties", "NonExistent"}
			line, _, _ := findNode(&node, path, "")

			Convey("It should return the last valid position", func() {
				So(line, ShouldBeGreaterThan, 0)
			})
		})

		Convey("When traversing a sequence", func() {
			yamlContent := `Resources:
  SecurityGroup:
    Properties:
      Ingress:
        - Port: 22
        - Port: 80
        - Port: 443
`

			var node yaml.Node
			err := yaml.Unmarshal([]byte(yamlContent), &node)
			So(err, ShouldBeNil)

			Convey("With int index", func() {
				path := []interface{}{"Resources", "SecurityGroup", "Properties", "Ingress", 1}
				line, _, _ := findNode(&node, path, "")
				So(line, ShouldBeGreaterThan, 0)
			})

			Convey("With float64 index", func() {
				path := []interface{}{"Resources", "SecurityGroup", "Properties", "Ingress", float64(2)}
				line, _, _ := findNode(&node, path, "")
				So(line, ShouldBeGreaterThan, 0)
			})
		})

		Convey("When path is empty", func() {
			yamlContent := `key: value`

			var node yaml.Node
			err := yaml.Unmarshal([]byte(yamlContent), &node)
			So(err, ShouldBeNil)

			line, snippet, snippetLines := findNode(&node, []interface{}{}, "")

			Convey("It should return 0", func() {
				So(line, ShouldEqual, 0)
				So(snippet, ShouldBeEmpty)
				So(snippetLines, ShouldBeNil)
			})
		})

		Convey("When node is nil", func() {
			line, snippet, snippetLines := findNode(nil, []interface{}{"key"}, "")

			Convey("It should return 0", func() {
				So(line, ShouldEqual, 0)
				So(snippet, ShouldBeEmpty)
				So(snippetLines, ShouldBeNil)
			})
		})
	})
}

func TestTraverseNode(t *testing.T) {
	Convey("Given the traverseNode function", t, func() {
		Convey("When node is nil", func() {
			result := traverseNode(nil, "key")

			Convey("It should return nil", func() {
				So(result, ShouldBeNil)
			})
		})

		Convey("When traversing sequence with invalid string index", func() {
			yamlContent := `list:
  - item1
  - item2
`

			var node yaml.Node
			err := yaml.Unmarshal([]byte(yamlContent), &node)
			So(err, ShouldBeNil)

			listNode := node.Content[0].Content[1]
			result := traverseNode(listNode, "invalid")

			Convey("It should return nil", func() {
				So(result, ShouldBeNil)
			})
		})

		Convey("When traversing sequence with out of bounds index", func() {
			yamlContent := `list:
  - item1
  - item2
`

			var node yaml.Node
			err := yaml.Unmarshal([]byte(yamlContent), &node)
			So(err, ShouldBeNil)

			listNode := node.Content[0].Content[1]

			Convey("With index 100", func() {
				result := traverseNode(listNode, 100)
				So(result, ShouldBeNil)
			})

			Convey("With negative index", func() {
				result := traverseNode(listNode, -1)
				So(result, ShouldBeNil)
			})
		})
	})
}
