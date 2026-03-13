// Package lsp implements a Language Server Protocol server for ROS templates.
package lsp

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/lsp/document"
	"github.com/aliyun/infraguard/pkg/lsp/protocol"
	"github.com/aliyun/infraguard/pkg/lsp/schema"
	"github.com/aliyun/infraguard/pkg/lsp/template"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/channel"
	"github.com/creachadair/jrpc2/handler"
)

// Server is the ROS LSP server.
type Server struct {
	mu         sync.Mutex
	store      *document.Store
	registry   *schema.Registry
	provider   *template.ROSTemplateProvider
	jrpcServer *jrpc2.Server
	shutdown   bool
}

// NewServer creates a new LSP server.
func NewServer() *Server {
	return &Server{
		store:    document.NewStore(),
		registry: schema.DefaultRegistry(),
		provider: &template.ROSTemplateProvider{},
	}
}

// Run starts the LSP server on stdin/stdout.
func (s *Server) Run() error {
	mux := s.buildMux()

	ch := channel.LSP(os.Stdin, os.Stdout)
	s.jrpcServer = jrpc2.NewServer(mux, &jrpc2.ServerOptions{
		AllowPush: true,
	})

	return s.jrpcServer.Start(ch).Wait()
}

func (s *Server) buildMux() handler.Map {
	return handler.Map{
		"initialize":             handler.New(s.handleInitialize),
		"initialized":           handler.New(s.handleInitialized),
		"shutdown":              handler.New(s.handleShutdown),
		"exit":                  handler.New(s.handleExit),
		"textDocument/didOpen":  handler.New(s.handleDidOpen),
		"textDocument/didChange": handler.New(s.handleDidChange),
		"textDocument/didClose": handler.New(s.handleDidClose),
		"textDocument/completion": handler.New(s.handleCompletion),
		"textDocument/hover":    handler.New(s.handleHover),
	}
}

// --- Lifecycle handlers ---

func (s *Server) handleInitialize(ctx context.Context, params *protocol.InitializeParams) (*protocol.InitializeResult, error) {
	if params.Locale != "" {
		i18n.SetLanguage(params.Locale)
	}

	return &protocol.InitializeResult{
		Capabilities: protocol.ServerCapabilities{
			TextDocumentSync: &protocol.TextDocumentSyncOptions{
				OpenClose: true,
				Change:    1, // Full sync
			},
			CompletionProvider: &protocol.CompletionOptions{
				TriggerCharacters: []string{":", ".", "!", " "},
			},
			HoverProvider: true,
		},
	}, nil
}

func (s *Server) handleInitialized(ctx context.Context, _ *json.RawMessage) error {
	log.Printf("[LSP] server ready, %d resource types loaded", s.registry.ResourceTypeCount())
	return nil
}

func (s *Server) handleShutdown(ctx context.Context, _ *json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdown = true
	return nil
}

func (s *Server) handleExit(ctx context.Context, _ *json.RawMessage) error {
	s.mu.Lock()
	isShutdown := s.shutdown
	s.mu.Unlock()

	if isShutdown {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
	return nil
}

// --- Document sync handlers ---

func (s *Server) handleDidOpen(ctx context.Context, params *protocol.DidOpenTextDocumentParams) error {
	s.store.Open(params.TextDocument.URI, params.TextDocument.LanguageID, params.TextDocument.Version, params.TextDocument.Text)
	s.publishDiagnostics(ctx, params.TextDocument.URI)
	return nil
}

func (s *Server) handleDidChange(ctx context.Context, params *protocol.DidChangeTextDocumentParams) error {
	if len(params.ContentChanges) > 0 {
		lastChange := params.ContentChanges[len(params.ContentChanges)-1]

		oldDoc := s.store.Get(params.TextDocument.URI)
		var oldContent string
		var isYAML, isROS bool
		if oldDoc != nil {
			oldContent = oldDoc.Content
			isYAML = oldDoc.IsYAML()
			isROS = oldDoc.IsROSTemplate()
		}

		s.store.Update(params.TextDocument.URI, params.TextDocument.Version, lastChange.Text)

		if isROS && oldContent != "" {
			version := params.TextDocument.Version
			go s.autoInsertProperties(params.TextDocument.URI, version, oldContent, lastChange.Text, isYAML)
		}
	}
	s.publishDiagnostics(ctx, params.TextDocument.URI)
	return nil
}

func (s *Server) handleDidClose(ctx context.Context, params *protocol.DidCloseTextDocumentParams) error {
	s.store.Close(params.TextDocument.URI)
	s.pushDiagnostics(ctx, params.TextDocument.URI, nil)
	return nil
}

// --- Feature handlers (stubs to be filled in later tasks) ---

func (s *Server) handleCompletion(ctx context.Context, params *protocol.CompletionParams) (*protocol.CompletionList, error) {
	doc := s.store.Get(params.TextDocument.URI)
	if doc == nil || !doc.IsROSTemplate() {
		return &protocol.CompletionList{Items: []protocol.CompletionItem{}}, nil
	}

	cctx := template.CompletionContext{
		URI:      doc.URI,
		Content:  doc.Content,
		Line:     params.Position.Line,
		Col:      params.Position.Character,
		IsYAML:   doc.IsYAML(),
		Registry: s.registry,
	}
	items := s.provider.Complete(cctx)
	if items == nil {
		items = []protocol.CompletionItem{}
	}
	return &protocol.CompletionList{Items: items}, nil
}

func (s *Server) handleHover(ctx context.Context, params *protocol.HoverParams) (*protocol.Hover, error) {
	doc := s.store.Get(params.TextDocument.URI)
	if doc == nil || !doc.IsROSTemplate() {
		return nil, nil
	}

	hctx := template.HoverContext{
		URI:      doc.URI,
		Content:  doc.Content,
		Line:     params.Position.Line,
		Col:      params.Position.Character,
		IsYAML:   doc.IsYAML(),
		Registry: s.registry,
	}
	result := s.provider.Hover(hctx)
	if result == nil {
		return nil, nil
	}
	return &protocol.Hover{
		Contents: protocol.Markup{
			Kind:  protocol.MarkupKindMarkdown,
			Value: result.Contents,
		},
		Range: result.Range,
	}, nil
}

// --- Diagnostics ---

func (s *Server) publishDiagnostics(ctx context.Context, uri string) {
	doc := s.store.Get(uri)
	if doc == nil || !doc.IsROSTemplate() {
		s.pushDiagnostics(ctx, uri, nil)
		return
	}

	vctx := template.ValidationContext{
		URI:      doc.URI,
		Content:  doc.Content,
		IsYAML:   doc.IsYAML(),
		Registry: s.registry,
	}
	diagnostics := s.provider.Validate(vctx)
	s.pushDiagnostics(ctx, uri, diagnostics)
}

// autoInsertProperties detects when a user presses Enter after a Type line
// with a valid resource type that has required properties, and auto-inserts
// the Properties section with required property keys.
func (s *Server) autoInsertProperties(uri string, docVersion int, oldContent, newContent string, isYAML bool) {
	insertedLine := findNewlyInsertedLine(oldContent, newContent)
	if insertedLine <= 0 {
		return
	}

	newLines := strings.Split(newContent, "\n")
	if insertedLine >= len(newLines) {
		return
	}

	if strings.TrimSpace(newLines[insertedLine]) != "" {
		return
	}

	prevLine := newLines[insertedLine-1]
	trimmed := strings.TrimSpace(prevLine)

	var typeName string
	if isYAML {
		if !strings.HasPrefix(trimmed, "Type:") {
			return
		}
		typeName = strings.TrimSpace(strings.TrimPrefix(trimmed, "Type:"))
	} else {
		typeName = template.ExtractJSONTypeValue(prevLine)
	}

	if typeName == "" || !s.registry.HasResourceType(typeName) {
		return
	}

	required := s.registry.RequiredProperties(typeName)
	if len(required) == 0 {
		return
	}

	if template.HasPropertiesSection(newContent, insertedLine-1) {
		return
	}

	indent := template.CountIndent(prevLine)
	indentStep := template.DetectIndentStep(newLines, insertedLine-1)
	indentStr := strings.Repeat(" ", indent)
	propIndentStr := strings.Repeat(" ", indent+indentStep)

	var edits []protocol.TextEdit

	if isYAML {
		propsText := indentStr + "Properties:"
		for _, prop := range required {
			propsText += "\n" + propIndentStr + prop + ": "
		}
		edits = append(edits, protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: insertedLine, Character: 0},
				End:   protocol.Position{Line: insertedLine, Character: len(newLines[insertedLine])},
			},
			NewText: propsText,
		})
	} else {
		// Ensure comma after Type value
		if !strings.HasSuffix(trimmed, ",") {
			commaPos := len(strings.TrimRight(prevLine, " \t"))
			edits = append(edits, protocol.TextEdit{
				Range: protocol.Range{
					Start: protocol.Position{Line: insertedLine - 1, Character: commaPos},
					End:   protocol.Position{Line: insertedLine - 1, Character: commaPos},
				},
				NewText: ",",
			})
		}

		propsText := indentStr + `"Properties": {`
		for i, prop := range required {
			propsText += "\n" + propIndentStr + `"` + prop + `": ""`
			if i < len(required)-1 {
				propsText += ","
			}
		}
		propsText += "\n" + indentStr + "}"
		edits = append(edits, protocol.TextEdit{
			Range: protocol.Range{
				Start: protocol.Position{Line: insertedLine, Character: 0},
				End:   protocol.Position{Line: insertedLine, Character: len(newLines[insertedLine])},
			},
			NewText: propsText,
		})
	}

	edit := protocol.WorkspaceEdit{
		DocumentChanges: []protocol.TextDocumentEdit{
			{
				TextDocument: protocol.OptionalVersionedTextDocumentIdentifier{
					URI:     uri,
					Version: &docVersion,
				},
				Edits: edits,
			},
		},
	}

	applyParams := protocol.ApplyWorkspaceEditParams{
		Label: "Auto-insert required properties",
		Edit:  edit,
	}

	ctx := context.Background()
	if s.jrpcServer != nil {
		if _, err := s.jrpcServer.Callback(ctx, "workspace/applyEdit", applyParams); err != nil {
			log.Printf("[LSP] auto-insert properties failed: %v", err)
		}
	}
}

// findNewlyInsertedLine detects when exactly one new line was inserted and returns its index.
// Returns -1 if the change is not a single line insertion.
func findNewlyInsertedLine(oldContent, newContent string) int {
	oldLines := strings.Split(oldContent, "\n")
	newLines := strings.Split(newContent, "\n")

	if len(newLines) != len(oldLines)+1 {
		return -1
	}

	for i := 0; i < len(oldLines); i++ {
		if i >= len(newLines) || oldLines[i] != newLines[i] {
			match := true
			for j := i; j < len(oldLines); j++ {
				if j+1 >= len(newLines) || oldLines[j] != newLines[j+1] {
					match = false
					break
				}
			}
			if match {
				return i
			}
			return -1
		}
	}
	return len(oldLines)
}

func (s *Server) pushDiagnostics(ctx context.Context, uri string, diagnostics []protocol.Diagnostic) {
	if diagnostics == nil {
		diagnostics = []protocol.Diagnostic{}
	}
	params := protocol.PublishDiagnosticsParams{
		URI:         uri,
		Diagnostics: diagnostics,
	}
	if s.jrpcServer != nil {
		if err := s.jrpcServer.Notify(ctx, "textDocument/publishDiagnostics", params); err != nil {
			log.Printf("[LSP] failed to push diagnostics for %s: %v", uri, err)
		}
	}
}
