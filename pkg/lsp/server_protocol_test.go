package lsp

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/infraguard/pkg/lsp/protocol"
	"github.com/aliyun/infraguard/pkg/lsp/schema"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
)

func TestExitNotificationUsesShutdownStatus(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		want        int
	}{{"after shutdown", "shutdown", 0}, {"without shutdown", "running", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestExitNotificationHelper$")
			cmd.Env = append(os.Environ(), "INFRAGUARD_LSP_EXIT_TEST="+tc.state)
			err := cmd.Run()
			if tc.want == 0 {
				if err != nil {
					t.Fatalf("exit status: %v", err)
				}
				return
			}
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != tc.want {
				t.Fatalf("exit status: %v", err)
			}
		})
	}
}

func TestExitNotificationHelper(t *testing.T) {
	state := os.Getenv("INFRAGUARD_LSP_EXIT_TEST")
	if state != "shutdown" && state != "running" {
		return
	}
	s := &Server{shutdown: state == "shutdown"}
	_ = s.handleExit(context.Background(), nil)
	t.Fatal("exit handler returned")
}

func TestEditorRequestsForUnsupportedOrMissingDocuments(t *testing.T) {
	s := NewServer()
	s.store.Open("file:///notes.txt", "plaintext", 1, "not a template")
	for _, uri := range []string{"file:///missing.yaml", "file:///notes.txt"} {
		pos := protocol.TextDocumentPositionParams{TextDocument: protocol.TextDocumentIdentifier{URI: uri}}
		completion, err := s.handleCompletion(context.Background(), &protocol.CompletionParams{TextDocumentPositionParams: pos})
		if err != nil || completion == nil || completion.Items == nil || len(completion.Items) != 0 {
			t.Fatalf("completion for %s: %+v %v", uri, completion, err)
		}
		hover, err := s.handleHover(context.Background(), &protocol.HoverParams{TextDocumentPositionParams: pos})
		if err != nil || hover != nil {
			t.Fatalf("hover for %s: %+v %v", uri, hover, err)
		}
		definition, err := s.handleDefinition(context.Background(), &protocol.DefinitionParams{TextDocumentPositionParams: pos})
		if err != nil || definition != nil {
			t.Fatalf("definition for %s: %+v %v", uri, definition, err)
		}
		s.publishDiagnostics(context.Background(), uri)
	}
}

func TestServerRunOverStdio(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	inputReader, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outputReader, outputWriter, err := os.Pipe()
	if err != nil {
		inputReader.Close()
		inputWriter.Close()
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inputReader, outputWriter
	s := NewServer()
	done := make(chan error, 1)
	go func() { done <- s.Run() }()
	client := jrpc2.NewClient(channel.LSP(outputReader, inputWriter), nil)
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("stdio server did not stop")
		}
		os.Stdin, os.Stdout = oldIn, oldOut
		inputReader.Close()
		outputReader.Close()
		outputWriter.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var result protocol.InitializeResult
	if err := client.CallResult(ctx, "initialize", &protocol.InitializeParams{}, &result); err != nil || result.Capabilities.CompletionProvider == nil {
		t.Fatalf("initialization over stdio: %+v %v", result, err)
	}
	if _, err := client.Call(ctx, "shutdown", nil); err != nil {
		t.Fatalf("shutdown over stdio: %v", err)
	}
}

func TestRPCDiagnosticsAndAutoInsert(t *testing.T) {
	s := NewServer()
	s.registry = &schema.Registry{}
	data := []byte(`{"resourceTypes":{"ALIYUN::TEST::Thing":{"properties":{"Name":{"type":"String","required":true},"Size":{"type":"Integer","required":true}}}}}`)
	if err := s.registry.LoadFromData(data); err != nil {
		t.Fatal(err)
	}
	clientChannel, serverChannel := channel.Direct()
	edits := make(chan protocol.ApplyWorkspaceEditParams, 2)
	diagnostics := make(chan protocol.PublishDiagnosticsParams, 4)
	client := jrpc2.NewClient(clientChannel, &jrpc2.ClientOptions{
		OnNotify: func(req *jrpc2.Request) {
			if req.Method() == "textDocument/publishDiagnostics" {
				var p protocol.PublishDiagnosticsParams
				if req.UnmarshalParams(&p) == nil {
					diagnostics <- p
				}
			}
		},
		OnCallback: func(_ context.Context, req *jrpc2.Request) (interface{}, error) {
			var p protocol.ApplyWorkspaceEditParams
			if err := req.UnmarshalParams(&p); err != nil {
				return nil, err
			}
			edits <- p
			return map[string]bool{"applied": true}, nil
		},
	})
	s.jrpcServer = jrpc2.NewServer(s.buildMux(), &jrpc2.ServerOptions{AllowPush: true}).Start(serverChannel)
	t.Cleanup(func() { client.Close(); _ = s.jrpcServer.Wait() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	uri := "file:///test.ros.yaml"
	open := protocol.DidOpenTextDocumentParams{TextDocument: protocol.TextDocumentItem{URI: uri, LanguageID: "ros-template-yaml", Version: 1, Text: "ROSTemplateFormatVersion: '2015-09-01'\nResources: {}\n"}}
	if _, err := client.Call(ctx, "textDocument/didOpen", open); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-diagnostics:
		if p.URI != uri {
			t.Fatalf("diagnostic URI: %s", p.URI)
		}
	case <-ctx.Done():
		t.Fatal("diagnostic notification timed out")
	}
	position := protocol.TextDocumentPositionParams{TextDocument: protocol.TextDocumentIdentifier{URI: uri}, Position: protocol.Position{Line: 1, Character: 3}}
	var hover protocol.Hover
	if err := client.CallResult(ctx, "textDocument/hover", protocol.HoverParams{TextDocumentPositionParams: position}, &hover); err != nil || !strings.Contains(hover.Contents.Value, "Resources") {
		t.Fatalf("hover: %+v %v", hover, err)
	}
	position.Position = protocol.Position{Line: 2, Character: 0}
	var completions protocol.CompletionList
	if err := client.CallResult(ctx, "textDocument/completion", protocol.CompletionParams{TextDocumentPositionParams: position}, &completions); err != nil || len(completions.Items) == 0 {
		t.Fatalf("completion: %+v %v", completions, err)
	}
	refURI := "file:///reference.ros.yaml"
	refContent := "ROSTemplateFormatVersion: '2015-09-01'\nParameters:\n  InstanceType:\n    Type: String\nResources:\n  MyECS:\n    Type: ALIYUN::ECS::Instance\n    Properties:\n      InstanceType:\n        Ref: InstanceType"
	if _, err := client.Call(ctx, "textDocument/didOpen", protocol.DidOpenTextDocumentParams{TextDocument: protocol.TextDocumentItem{URI: refURI, LanguageID: "ros-template-yaml", Version: 1, Text: refContent}}); err != nil {
		t.Fatal(err)
	}
	var location protocol.Location
	refPosition := protocol.TextDocumentPositionParams{TextDocument: protocol.TextDocumentIdentifier{URI: refURI}, Position: protocol.Position{Line: 9, Character: 15}}
	if err := client.CallResult(ctx, "textDocument/definition", protocol.DefinitionParams{TextDocumentPositionParams: refPosition}, &location); err != nil || location.URI != refURI || location.Range.Start.Line != 2 {
		t.Fatalf("definition: %+v %v", location, err)
	}
	old := "Resources:\n  Thing:\n    Type: ALIYUN::TEST::Thing\nNext: value"
	updated := "Resources:\n  Thing:\n    Type: ALIYUN::TEST::Thing\n\nNext: value"
	s.store.Open(uri, "ros-template-yaml", 1, old)
	change := protocol.DidChangeTextDocumentParams{
		TextDocument:   protocol.VersionedTextDocumentIdentifier{URI: uri, Version: 2},
		ContentChanges: []protocol.TextDocumentContentChangeEvent{{Text: updated}},
	}
	if _, err := client.Call(ctx, "textDocument/didChange", change); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-edits:
		if len(p.Edit.DocumentChanges) != 1 || len(p.Edit.DocumentChanges[0].Edits) != 1 || !strings.Contains(p.Edit.DocumentChanges[0].Edits[0].NewText, "Name:") {
			t.Fatalf("change-triggered edit: %+v", p)
		}
	case <-ctx.Done():
		t.Fatal("change-triggered edit timed out")
	}
	s.autoInsertProperties(uri, 2, old, updated, true)
	select {
	case p := <-edits:
		if len(p.Edit.DocumentChanges) != 1 || len(p.Edit.DocumentChanges[0].Edits) != 1 || !strings.Contains(p.Edit.DocumentChanges[0].Edits[0].NewText, "Name:") || !strings.Contains(p.Edit.DocumentChanges[0].Edits[0].NewText, "Size:") {
			b, _ := json.Marshal(p)
			t.Fatalf("YAML edit: %s", b)
		}
	case <-ctx.Done():
		t.Fatal("YAML edit timed out")
	}
	oldJSON := "{\n  \"Thing\": {\n    \"Type\": \"ALIYUN::TEST::Thing\"\n  }\n}"
	newJSON := "{\n  \"Thing\": {\n    \"Type\": \"ALIYUN::TEST::Thing\"\n\n  }\n}"
	s.autoInsertProperties(uri, 3, oldJSON, newJSON, false)
	select {
	case p := <-edits:
		if len(p.Edit.DocumentChanges) != 1 || len(p.Edit.DocumentChanges[0].Edits) != 2 || p.Edit.DocumentChanges[0].Edits[0].NewText != "," || !strings.Contains(p.Edit.DocumentChanges[0].Edits[1].NewText, `"Name"`) {
			t.Fatalf("JSON edit: %+v", p)
		}
	case <-ctx.Done():
		t.Fatal("JSON edit timed out")
	}
	s.autoInsertProperties(uri, 4, old, old, true)
	select {
	case <-edits:
		t.Fatal("unexpected edit without a new line")
	default:
	}
	for _, tc := range []struct {
		name, old, updated string
		yaml               bool
	}{
		{"unknown resource", "Resources:\n  Thing:\n    Type: Unknown", "Resources:\n  Thing:\n    Type: Unknown\n", true},
		{"other field", "Resources:\n  Thing:\n    Name: example", "Resources:\n  Thing:\n    Name: example\n", true},
		{"non-empty insertion", old, "Resources:\n  Thing:\n    Type: ALIYUN::TEST::Thing\n    Name: test\nNext: value", true},
		{"already has properties", "Resources:\n  Thing:\n    Type: ALIYUN::TEST::Thing\n    Properties: {}", "Resources:\n  Thing:\n    Type: ALIYUN::TEST::Thing\n\n    Properties: {}", true},
		{"JSON has properties", "{\n  \"Type\": \"ALIYUN::TEST::Thing\",\n  \"Properties\": {}\n}", "{\n  \"Type\": \"ALIYUN::TEST::Thing\",\n\n  \"Properties\": {}\n}", false},
	} {
		s.autoInsertProperties(uri, 4, tc.old, tc.updated, tc.yaml)
		select {
		case edit := <-edits:
			t.Errorf("%s: unexpected edit %+v", tc.name, edit)
		default:
		}
	}
}

func TestFindSingleInsertedLine(t *testing.T) {
	for _, tc := range []struct {
		old, updated string
		want         int
	}{
		{"a\nb", "x\na\nb", 0}, {"a\nb", "a\nx\nb", 1}, {"a\nb", "a\nb\nx", 2},
		{"a\nb", "a\nb", -1}, {"a\nb", "a\nx\nc", -1}, {"a", "a\nb\nc", -1},
	} {
		if got := findNewlyInsertedLine(tc.old, tc.updated); got != tc.want {
			t.Errorf("%q -> %q: %d, want %d", tc.old, tc.updated, got, tc.want)
		}
	}
}
