package lsp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aliyun/infraguard/pkg/lsp/protocol"
	. "github.com/smartystreets/goconvey/convey"
)

func TestServer_Initialize(t *testing.T) {
	Convey("Given a new LSP server", t, func() {
		server := NewServer()

		Convey("handleInitialize returns server capabilities", func() {
			params := &protocol.InitializeParams{
				RootURI: "file:///workspace",
				Locale:  "en",
			}
			result, err := server.handleInitialize(context.Background(), params)

			So(err, ShouldBeNil)
			So(result, ShouldNotBeNil)
			So(result.Capabilities.TextDocumentSync, ShouldNotBeNil)
			So(result.Capabilities.TextDocumentSync.OpenClose, ShouldBeTrue)
			So(result.Capabilities.CompletionProvider, ShouldNotBeNil)
			So(result.Capabilities.HoverProvider, ShouldBeTrue)
		})
	})
}

func TestServer_DocumentSync(t *testing.T) {
	Convey("Given a new LSP server", t, func() {
		server := NewServer()

		Convey("didOpen stores the document", func() {
			params := &protocol.DidOpenTextDocumentParams{
				TextDocument: protocol.TextDocumentItem{
					URI:        "file:///test.ros.yaml",
					LanguageID: "ros-template-yaml",
					Version:    1,
					Text:       "ROSTemplateFormatVersion: '2015-09-01'\nResources: {}",
				},
			}
			err := server.handleDidOpen(context.Background(), params)
			So(err, ShouldBeNil)

			doc := server.store.Get("file:///test.ros.yaml")
			So(doc, ShouldNotBeNil)
			So(doc.Content, ShouldContainSubstring, "ROSTemplateFormatVersion")
		})

		Convey("didChange updates document content", func() {
			server.store.Open("file:///test.yaml", "yaml", 1, "old content")

			params := &protocol.DidChangeTextDocumentParams{
				TextDocument: protocol.VersionedTextDocumentIdentifier{
					URI:     "file:///test.yaml",
					Version: 2,
				},
				ContentChanges: []protocol.TextDocumentContentChangeEvent{
					{Text: "ROSTemplateFormatVersion: '2015-09-01'\nnew content"},
				},
			}
			err := server.handleDidChange(context.Background(), params)
			So(err, ShouldBeNil)

			doc := server.store.Get("file:///test.yaml")
			So(doc, ShouldNotBeNil)
			So(doc.Content, ShouldContainSubstring, "new content")
			So(doc.Version, ShouldEqual, 2)
		})

		Convey("didClose removes the document", func() {
			server.store.Open("file:///test.yaml", "yaml", 1, "content")

			params := &protocol.DidCloseTextDocumentParams{
				TextDocument: protocol.TextDocumentIdentifier{
					URI: "file:///test.yaml",
				},
			}
			err := server.handleDidClose(context.Background(), params)
			So(err, ShouldBeNil)

			doc := server.store.Get("file:///test.yaml")
			So(doc, ShouldBeNil)
		})
	})
}

func TestServer_Completion(t *testing.T) {
	Convey("Given a server with an open ROS template", t, func() {
		server := NewServer()

		content := "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  MyECS:\n    Type: ALIYUN::ECS::Instance\n\n"
		server.store.Open("file:///test.ros.yaml", "ros-template-yaml", 1, content)

		Convey("completion at top level returns block completions", func() {
			params := &protocol.CompletionParams{
				TextDocumentPositionParams: protocol.TextDocumentPositionParams{
					TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.ros.yaml"},
					Position:     protocol.Position{Line: 4, Character: 0},
				},
			}
			result, err := server.handleCompletion(context.Background(), params)
			So(err, ShouldBeNil)
			So(result, ShouldNotBeNil)
			So(len(result.Items), ShouldBeGreaterThan, 0)
		})

		Convey("completion returns empty for non-ROS documents", func() {
			server.store.Open("file:///regular.yaml", "yaml", 1, "key: value")

			params := &protocol.CompletionParams{
				TextDocumentPositionParams: protocol.TextDocumentPositionParams{
					TextDocument: protocol.TextDocumentIdentifier{URI: "file:///regular.yaml"},
					Position:     protocol.Position{Line: 0, Character: 0},
				},
			}
			result, err := server.handleCompletion(context.Background(), params)
			So(err, ShouldBeNil)
			So(result, ShouldNotBeNil)
			So(len(result.Items), ShouldEqual, 0)
		})
	})
}

func TestServer_Hover(t *testing.T) {
	Convey("Given a server with an open ROS template", t, func() {
		server := NewServer()

		content := "ROSTemplateFormatVersion: '2015-09-01'\nResources:\n  MyECS:\n    Type: ALIYUN::ECS::Instance\n"
		server.store.Open("file:///test.ros.yaml", "ros-template-yaml", 1, content)

		Convey("hover on Resources returns info", func() {
			params := &protocol.HoverParams{
				TextDocumentPositionParams: protocol.TextDocumentPositionParams{
					TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.ros.yaml"},
					Position:     protocol.Position{Line: 1, Character: 3},
				},
			}
			result, err := server.handleHover(context.Background(), params)
			So(err, ShouldBeNil)
			So(result, ShouldNotBeNil)
			So(result.Contents.Value, ShouldContainSubstring, "Resources")
		})

		Convey("hover returns nil for non-ROS documents", func() {
			server.store.Open("file:///regular.yaml", "yaml", 1, "key: value")

			params := &protocol.HoverParams{
				TextDocumentPositionParams: protocol.TextDocumentPositionParams{
					TextDocument: protocol.TextDocumentIdentifier{URI: "file:///regular.yaml"},
					Position:     protocol.Position{Line: 0, Character: 0},
				},
			}
			result, err := server.handleHover(context.Background(), params)
			So(err, ShouldBeNil)
			So(result, ShouldBeNil)
		})
	})
}

func TestServer_Shutdown(t *testing.T) {
	Convey("Given a new LSP server", t, func() {
		server := NewServer()

		Convey("shutdown sets shutdown flag", func() {
			err := server.handleShutdown(context.Background(), nil)
			So(err, ShouldBeNil)
			So(server.shutdown, ShouldBeTrue)
		})

		Convey("initialized logs without error", func() {
			var raw json.RawMessage
			err := server.handleInitialized(context.Background(), &raw)
			So(err, ShouldBeNil)
		})
	})
}
