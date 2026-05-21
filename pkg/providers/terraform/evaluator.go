package terraform

import (
	"fmt"
	"path/filepath"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// VariableDef represents a Terraform variable definition.
type VariableDef struct {
	Name    string
	Type    cty.Type
	Default cty.Value
}

// EvalResult holds the fully evaluated Terraform configuration.
type EvalResult struct {
	Resources   map[string]map[string]map[string]interface{}
	Variables   map[string]interface{}
	Locals      map[string]interface{}
	DataSources map[string]map[string]map[string]interface{}
	Outputs     map[string]interface{}
}

// UnknownValue is a placeholder for values that cannot be resolved.
const UnknownValue = "<unknown>"

// extractVariables parses all variable blocks from the config.
func extractVariables(parsed *ParsedConfig) (map[string]*VariableDef, hcl.Diagnostics) {
	vars := make(map[string]*VariableDef)
	var allDiags hcl.Diagnostics

	for _, file := range parsed.Files {
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, block := range body.Blocks {
			if block.Type != "variable" || len(block.Labels) == 0 {
				continue
			}
			name := block.Labels[0]
			varDef := &VariableDef{Name: name, Type: cty.DynamicPseudoType, Default: cty.NilVal}

			attrs, diags := block.Body.JustAttributes()
			allDiags = append(allDiags, diags...)

			if defaultAttr, exists := attrs["default"]; exists {
				val, diags := defaultAttr.Expr.Value(nil)
				allDiags = append(allDiags, diags...)
				if !diags.HasErrors() {
					varDef.Default = val
				}
			}

			vars[name] = varDef
		}
	}
	return vars, allDiags
}

// buildEvalContext creates an HCL evaluation context with var.* and local.* references.
func buildEvalContext(vars map[string]*VariableDef, locals map[string]cty.Value, inputVars map[string]interface{}) *hcl.EvalContext {
	varValues := make(map[string]cty.Value)
	for name, def := range vars {
		if inputVal, ok := inputVars[name]; ok {
			varValues[name] = goToCty(inputVal)
		} else if def.Default != cty.NilVal {
			varValues[name] = def.Default
		} else {
			varValues[name] = cty.StringVal(UnknownValue)
		}
	}

	localValues := make(map[string]cty.Value)
	if locals != nil {
		for k, v := range locals {
			localValues[k] = v
		}
	}

	// cty.ObjectVal panics on empty maps, use cty.EmptyObjectVal instead
	var varObj cty.Value
	if len(varValues) == 0 {
		varObj = cty.EmptyObjectVal
	} else {
		varObj = cty.ObjectVal(varValues)
	}

	var localObj cty.Value
	if len(localValues) == 0 {
		localObj = cty.EmptyObjectVal
	} else {
		localObj = cty.ObjectVal(localValues)
	}

	return &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var":   varObj,
			"local": localObj,
		},
	}
}

// extractLocals evaluates all locals blocks from the config.
func extractLocals(parsed *ParsedConfig, ctx *hcl.EvalContext) (map[string]cty.Value, hcl.Diagnostics) {
	locals := make(map[string]cty.Value)
	var allDiags hcl.Diagnostics

	for _, file := range parsed.Files {
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, block := range body.Blocks {
			if block.Type != "locals" {
				continue
			}
			attrs, diags := block.Body.JustAttributes()
			allDiags = append(allDiags, diags...)
			for name, attr := range attrs {
				val, diags := attr.Expr.Value(ctx)
				if diags.HasErrors() {
					locals[name] = cty.StringVal(UnknownValue)
				} else {
					locals[name] = val
				}
			}
		}
	}
	return locals, allDiags
}

// evaluate resolves the full Terraform configuration into concrete Go values.
func evaluate(parsed *ParsedConfig, inputVars map[string]interface{}) (*EvalResult, error) {
	vars, diags := extractVariables(parsed)
	if diags.HasErrors() {
		return nil, fmt.Errorf("variable extraction: %s", diags.Error())
	}

	// First pass: build context with variables only to resolve locals
	evalCtx := buildEvalContext(vars, nil, inputVars)
	locals, _ := extractLocals(parsed, evalCtx)

	// Second pass: rebuild context with both variables and locals
	evalCtx = buildEvalContext(vars, locals, inputVars)

	result := &EvalResult{
		Resources:   make(map[string]map[string]map[string]interface{}),
		Variables:   make(map[string]interface{}),
		Locals:      make(map[string]interface{}),
		DataSources: make(map[string]map[string]map[string]interface{}),
		Outputs:     make(map[string]interface{}),
	}

	// Populate variables in result
	for name, def := range vars {
		if inputVal, ok := inputVars[name]; ok {
			result.Variables[name] = map[string]interface{}{"value": inputVal}
		} else if def.Default != cty.NilVal {
			result.Variables[name] = map[string]interface{}{"value": ctyToGo(def.Default)}
		} else {
			result.Variables[name] = map[string]interface{}{"value": UnknownValue}
		}
	}

	// Populate locals in result
	for name, val := range locals {
		result.Locals[name] = ctyToGo(val)
	}

	// Evaluate resource, data, and output blocks
	for filePath, file := range parsed.Files {
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, block := range body.Blocks {
			switch block.Type {
			case "resource":
				if len(block.Labels) < 2 {
					continue
				}
				resType := block.Labels[0]
				resName := block.Labels[1]
				attrs := evaluateBlockAttrs(block.Body, evalCtx)
				attrs["__meta__"] = map[string]interface{}{
					"filename": filepath.Base(filePath),
					"line":     block.DefRange().Start.Line,
				}
				if result.Resources[resType] == nil {
					result.Resources[resType] = make(map[string]map[string]interface{})
				}
				result.Resources[resType][resName] = attrs

			case "data":
				if len(block.Labels) < 2 {
					continue
				}
				dsType := block.Labels[0]
				dsName := block.Labels[1]
				attrs := evaluateBlockAttrs(block.Body, evalCtx)
				attrs["__meta__"] = map[string]interface{}{
					"filename": filepath.Base(filePath),
					"line":     block.DefRange().Start.Line,
				}
				if result.DataSources[dsType] == nil {
					result.DataSources[dsType] = make(map[string]map[string]interface{})
				}
				result.DataSources[dsType][dsName] = attrs

			case "output":
				if len(block.Labels) < 1 {
					continue
				}
				outputName := block.Labels[0]
				attrs := evaluateBlockAttrs(block.Body, evalCtx)
				result.Outputs[outputName] = attrs
			}
		}
	}

	return result, nil
}

// evaluateBlockAttrs evaluates all attributes in a block body.
func evaluateBlockAttrs(body *hclsyntax.Body, ctx *hcl.EvalContext) map[string]interface{} {
	result := make(map[string]interface{})
	attrs, _ := body.JustAttributes()
	for name, attr := range attrs {
		val, diags := attr.Expr.Value(ctx)
		if diags.HasErrors() {
			result[name] = UnknownValue
		} else {
			result[name] = ctyToGo(val)
		}
	}
	for _, block := range body.Blocks {
		if block.Type == "dynamic" {
			continue
		}
		nested := evaluateBlockAttrs(block.Body, ctx)
		if existing, ok := result[block.Type]; ok {
			if existingList, ok := existing.([]interface{}); ok {
				result[block.Type] = append(existingList, nested)
			} else {
				result[block.Type] = []interface{}{existing, nested}
			}
		} else {
			result[block.Type] = nested
		}
	}
	return result
}

// goToCty converts a Go value to a cty.Value.
func goToCty(v interface{}) cty.Value {
	switch val := v.(type) {
	case string:
		return cty.StringVal(val)
	case float64:
		return cty.NumberFloatVal(val)
	case int:
		return cty.NumberIntVal(int64(val))
	case bool:
		return cty.BoolVal(val)
	case nil:
		return cty.NullVal(cty.DynamicPseudoType)
	default:
		return cty.StringVal(fmt.Sprintf("%v", val))
	}
}

// ctyToGo converts a cty.Value to a native Go value.
func ctyToGo(val cty.Value) interface{} {
	if !val.IsKnown() {
		return UnknownValue
	}
	if val.IsNull() {
		return nil
	}

	ty := val.Type()
	switch {
	case ty == cty.String:
		return val.AsString()
	case ty == cty.Number:
		bf := val.AsBigFloat()
		f, _ := bf.Float64()
		if bf.IsInt() {
			i, _ := bf.Int64()
			return float64(i)
		}
		return f
	case ty == cty.Bool:
		return val.True()
	case ty.IsListType() || ty.IsTupleType() || ty.IsSetType():
		var result []interface{}
		for it := val.ElementIterator(); it.Next(); {
			_, v := it.Element()
			result = append(result, ctyToGo(v))
		}
		return result
	case ty.IsMapType() || ty.IsObjectType():
		result := make(map[string]interface{})
		for it := val.ElementIterator(); it.Next(); {
			k, v := it.Element()
			result[k.AsString()] = ctyToGo(v)
		}
		return result
	default:
		return UnknownValue
	}
}
