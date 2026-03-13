package document

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestStore(t *testing.T) {
	Convey("Given a new Store", t, func() {
		store := NewStore()

		Convey("Open adds a document", func() {
			doc := store.Open("file:///test.yaml", "yaml", 1, "key: value\nfoo: bar\n")
			So(doc, ShouldNotBeNil)
			So(doc.URI, ShouldEqual, "file:///test.yaml")
			So(doc.LanguageID, ShouldEqual, "yaml")
			So(doc.Version, ShouldEqual, 1)
			So(doc.LineCount(), ShouldEqual, 3)
			So(doc.GetLine(0), ShouldEqual, "key: value")
			So(doc.GetLine(1), ShouldEqual, "foo: bar")
		})

		Convey("Get returns the opened document", func() {
			store.Open("file:///test.yaml", "yaml", 1, "content")
			doc := store.Get("file:///test.yaml")
			So(doc, ShouldNotBeNil)
			So(doc.Content, ShouldEqual, "content")
		})

		Convey("Get returns nil for unknown document", func() {
			doc := store.Get("file:///unknown.yaml")
			So(doc, ShouldBeNil)
		})

		Convey("Update changes document content", func() {
			store.Open("file:///test.yaml", "yaml", 1, "old content")
			doc := store.Update("file:///test.yaml", 2, "new content")
			So(doc, ShouldNotBeNil)
			So(doc.Content, ShouldEqual, "new content")
			So(doc.Version, ShouldEqual, 2)
		})

		Convey("Update returns nil for unknown document", func() {
			doc := store.Update("file:///unknown.yaml", 1, "content")
			So(doc, ShouldBeNil)
		})

		Convey("Close removes the document", func() {
			store.Open("file:///test.yaml", "yaml", 1, "content")
			store.Close("file:///test.yaml")
			doc := store.Get("file:///test.yaml")
			So(doc, ShouldBeNil)
		})
	})
}

func TestDocument_IsROSTemplate(t *testing.T) {
	Convey("Given documents with various language IDs", t, func() {
		Convey("ros-template-yaml is always a ROS template", func() {
			doc := &Document{LanguageID: "ros-template-yaml", Content: ""}
			So(doc.IsROSTemplate(), ShouldBeTrue)
		})

		Convey("ros-template-json is always a ROS template", func() {
			doc := &Document{LanguageID: "ros-template-json", Content: ""}
			So(doc.IsROSTemplate(), ShouldBeTrue)
		})

		Convey("yaml with ROSTemplateFormatVersion is a ROS template", func() {
			doc := &Document{LanguageID: "yaml", Content: "ROSTemplateFormatVersion: '2015-09-01'\nResources: {}"}
			So(doc.IsROSTemplate(), ShouldBeTrue)
		})

		Convey("yaml without ROSTemplateFormatVersion is not a ROS template", func() {
			doc := &Document{LanguageID: "yaml", Content: "key: value\nfoo: bar"}
			So(doc.IsROSTemplate(), ShouldBeFalse)
		})

		Convey("other language IDs are not ROS templates", func() {
			doc := &Document{LanguageID: "python", Content: "ROSTemplateFormatVersion"}
			So(doc.IsROSTemplate(), ShouldBeFalse)
		})
	})
}

func TestDocument_FormatDetection(t *testing.T) {
	Convey("Given documents with various language IDs", t, func() {
		Convey("yaml documents are YAML", func() {
			doc := &Document{LanguageID: "yaml"}
			So(doc.IsYAML(), ShouldBeTrue)
			So(doc.IsJSON(), ShouldBeFalse)
		})

		Convey("ros-template-yaml documents are YAML", func() {
			doc := &Document{LanguageID: "ros-template-yaml"}
			So(doc.IsYAML(), ShouldBeTrue)
			So(doc.IsJSON(), ShouldBeFalse)
		})

		Convey("json documents are JSON", func() {
			doc := &Document{LanguageID: "json"}
			So(doc.IsJSON(), ShouldBeTrue)
			So(doc.IsYAML(), ShouldBeFalse)
		})

		Convey("ros-template-json documents are JSON", func() {
			doc := &Document{LanguageID: "ros-template-json"}
			So(doc.IsJSON(), ShouldBeTrue)
			So(doc.IsYAML(), ShouldBeFalse)
		})
	})
}

func TestDocument_GetLine(t *testing.T) {
	Convey("Given a document with multiple lines", t, func() {
		doc := &Document{
			Content: "line1\nline2\nline3",
			Lines:   []string{"line1", "line2", "line3"},
		}

		Convey("GetLine returns correct lines", func() {
			So(doc.GetLine(0), ShouldEqual, "line1")
			So(doc.GetLine(1), ShouldEqual, "line2")
			So(doc.GetLine(2), ShouldEqual, "line3")
		})

		Convey("GetLine returns empty for out of range", func() {
			So(doc.GetLine(-1), ShouldEqual, "")
			So(doc.GetLine(3), ShouldEqual, "")
		})
	})
}
