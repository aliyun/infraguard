//go:build js && wasm

// Command infraguard-wasm exposes client-side ROS scanning to the browser for
// the documentation playground. It receives rule modules as data (the embedded
// policy index is too large to compile into a wasm init function), parses the
// template in memory, and evaluates it with the same OPA engine as the CLI.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/aliyun/infraguard/pkg/engine"
	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/mapper"
	"github.com/aliyun/infraguard/pkg/models"
	"gopkg.in/yaml.v3"
)

type modulePayload struct {
	LibModules map[string]string `json:"lib_modules"`
	Modules    map[string]string `json:"modules"`
}

// scan(content, modulesJSON, lang?) -> JSON string {violations} | {error}
func scan(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return errJSON("scan requires (content, modulesJSON)")
	}
	content := args[0].String()
	var payload modulePayload
	if err := json.Unmarshal([]byte(args[1].String()), &payload); err != nil {
		return errJSON("invalid modules payload: " + err.Error())
	}
	lang := "en"
	if len(args) > 2 && args[2].Type() == js.TypeString {
		lang = args[2].String()
	}

	var input map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &input); err != nil {
		return errJSON("template parse error: " + err.Error())
	}
	var root yaml.Node
	_ = yaml.Unmarshal([]byte(content), &root)

	opts := &engine.EvalOptions{Modules: payload.Modules, LibModules: payload.LibModules}
	res, err := engine.EvaluateWithOpts(opts, input)
	if err != nil {
		return errJSON(err.Error())
	}
	rich := mapper.MapViolationsWithLang(res.Violations, &root, "template.yaml", lang)
	if rich == nil {
		rich = []models.RichViolation{}
	}
	out, _ := json.Marshal(map[string]interface{}{"violations": rich})
	return string(out)
}

func errJSON(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}

func main() {
	i18n.SetLanguage("en")
	js.Global().Set("infraguardScan", js.FuncOf(scan))
	select {}
}
