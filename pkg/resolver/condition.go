package resolver

import (
	"fmt"

	"github.com/aliyun/infraguard/pkg/resolver/funcs"
)

// resolveConditions resolves all conditions in the Conditions section
// Returns a map of condition names to their boolean values
func resolveConditions(template map[string]interface{}, params map[string]interface{}) (map[string]bool, error) {
	conditionsSection, ok := template["Conditions"].(map[string]interface{})
	if !ok || len(conditionsSection) == 0 {
		// No conditions to resolve
		return make(map[string]bool), nil
	}

	// Build dependency graph
	graph := buildConditionGraph(conditionsSection)

	// Topological sort to handle dependencies
	sorted, err := topologicalSort(graph)
	if err != nil {
		return nil, err
	}

	// Evaluate conditions in dependency order
	results := make(map[string]bool)
	for _, condName := range sorted {
		condExpr := conditionsSection[condName]

		// Step 1: Replace condition references with their resolved boolean values
		processedExpr := replaceConditionReferences(condExpr, results)

		// Step 2: Resolve functions in the processed expression
		resolved, err := resolveValue(processedExpr, params, template)
		if err != nil {
			return nil, fmt.Errorf("error resolving condition %s: %w", condName, err)
		}

		// If still a function, we can't evaluate it
		if isFunction(resolved) {
			return nil, fmt.Errorf("condition %s cannot be statically evaluated", condName)
		}

		// Convert to boolean
		boolVal, err := funcs.ToBool(resolved)
		if err != nil {
			return nil, fmt.Errorf("condition %s: %w", condName, err)
		}

		results[condName] = boolVal
	}

	return results, nil
}

// replaceConditionReferences replaces condition name strings with their boolean values
func replaceConditionReferences(value interface{}, resolvedConditions map[string]bool) interface{} {
	switch v := value.(type) {
	case string:
		// Check if this is a condition reference
		if boolVal, exists := resolvedConditions[v]; exists {
			return boolVal
		}
		return v

	case []interface{}:
		// Recurse into array
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = replaceConditionReferences(item, resolvedConditions)
		}
		return result

	case map[string]interface{}:
		// Recurse into map
		result := make(map[string]interface{})
		for k, val := range v {
			result[k] = replaceConditionReferences(val, resolvedConditions)
		}
		return result

	default:
		// Scalar value, return as-is
		return v
	}
}

// conditionGraph represents dependencies between conditions
type conditionGraph struct {
	nodes    []string
	edges    map[string][]string // node -> list of nodes it depends on
	inDegree map[string]int
}

// buildConditionGraph builds a dependency graph for conditions
func buildConditionGraph(conditions map[string]interface{}) *conditionGraph {
	graph := &conditionGraph{
		nodes:    make([]string, 0, len(conditions)),
		edges:    make(map[string][]string),
		inDegree: make(map[string]int),
	}

	// Initialize nodes
	for condName := range conditions {
		graph.nodes = append(graph.nodes, condName)
		graph.edges[condName] = make([]string, 0)
		graph.inDegree[condName] = 0
	}

	// Find dependencies (condition references)
	for condName, condExpr := range conditions {
		deps := findConditionReferences(condExpr, conditions)
		for _, dep := range deps {
			// condName depends on dep, so dep must be evaluated before condName
			// Therefore, condName has an incoming edge from dep
			graph.edges[dep] = append(graph.edges[dep], condName)
			graph.inDegree[condName]++
		}
	}

	return graph
}

// findConditionReferences finds all condition references in an expression
func findConditionReferences(value interface{}, conditions map[string]interface{}) []string {
	refs := make([]string, 0)

	switch v := value.(type) {
	case map[string]interface{}:
		// Check if this is a condition reference (string that matches a condition name)
		if len(v) == 1 {
			for key, val := range v {
				if key == "Condition" {
					// Direct condition reference
					if str, ok := val.(string); ok {
						if _, exists := conditions[str]; exists {
							refs = append(refs, str)
						}
					}
				} else if key == "Fn::If" {
					// Fn::If may reference a condition
					if arr, ok := val.([]interface{}); ok && len(arr) >= 1 {
						if str, ok := arr[0].(string); ok {
							if _, exists := conditions[str]; exists {
								refs = append(refs, str)
							}
						}
					}
					// Also check the rest of the If expression
					if arr, ok := val.([]interface{}); ok {
						for _, item := range arr {
							refs = append(refs, findConditionReferences(item, conditions)...)
						}
					}
				} else {
					// Recurse into other functions
					refs = append(refs, findConditionReferences(val, conditions)...)
				}
			}
		} else {
			// Regular map, recurse
			for _, val := range v {
				refs = append(refs, findConditionReferences(val, conditions)...)
			}
		}

	case []interface{}:
		for _, item := range v {
			refs = append(refs, findConditionReferences(item, conditions)...)
		}

	case string:
		// Check if this string is a condition name (direct reference)
		if _, exists := conditions[v]; exists {
			refs = append(refs, v)
		}
	}

	return refs
}

// topologicalSort performs Kahn's algorithm for topological sorting
// Returns sorted list of condition names or error if cycle detected
func topologicalSort(graph *conditionGraph) ([]string, error) {
	// Make a copy of inDegree to avoid modifying the original
	inDegree := make(map[string]int)
	for k, v := range graph.inDegree {
		inDegree[k] = v
	}

	// Find all nodes with in-degree 0
	queue := make([]string, 0)
	for _, node := range graph.nodes {
		if inDegree[node] == 0 {
			queue = append(queue, node)
		}
	}

	sorted := make([]string, 0, len(graph.nodes))

	for len(queue) > 0 {
		// Dequeue
		current := queue[0]
		queue = queue[1:]
		sorted = append(sorted, current)

		// Reduce in-degree for dependent nodes
		for _, dependent := range graph.edges[current] {
			inDegree[dependent]--
			if inDegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}

	// Check for cycles
	if len(sorted) != len(graph.nodes) {
		// Find nodes involved in cycle
		cycleNodes := make([]string, 0)
		for _, node := range graph.nodes {
			if inDegree[node] > 0 {
				cycleNodes = append(cycleNodes, node)
			}
		}
		return nil, fmt.Errorf("circular dependency detected in conditions: %v", cycleNodes)
	}

	return sorted, nil
}

// applyConditionsToResources removes resources with false conditions
func applyConditionsToResources(template map[string]interface{}, conditions map[string]bool) {
	resources, ok := template["Resources"].(map[string]interface{})
	if !ok {
		return
	}

	// Find resources to remove
	toRemove := make([]string, 0)
	for resName, resValue := range resources {
		resMap, ok := resValue.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if resource has a Condition
		if condNameRaw, hasCondition := resMap["Condition"]; hasCondition {
			condName, ok := condNameRaw.(string)
			if !ok {
				continue
			}

			// Check condition result
			condResult, exists := conditions[condName]
			if !exists {
				// Condition doesn't exist - remove the resource (conservative approach)
				toRemove = append(toRemove, resName)
			} else if !condResult {
				// Condition is false - remove the resource
				toRemove = append(toRemove, resName)
			}
		}
	}

	// Remove resources with false conditions
	for _, resName := range toRemove {
		delete(resources, resName)
	}
}

// applyConditionsToOutputs removes outputs with false conditions
func applyConditionsToOutputs(template map[string]interface{}, conditions map[string]bool) {
	outputs, ok := template["Outputs"].(map[string]interface{})
	if !ok {
		return
	}

	// Find outputs to remove
	toRemove := make([]string, 0)
	for outName, outValue := range outputs {
		outMap, ok := outValue.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if output has a Condition
		if condNameRaw, hasCondition := outMap["Condition"]; hasCondition {
			condName, ok := condNameRaw.(string)
			if !ok {
				continue
			}

			// Check condition result
			condResult, exists := conditions[condName]
			if !exists {
				// Condition doesn't exist - remove the output (conservative approach)
				toRemove = append(toRemove, outName)
			} else if !condResult {
				// Condition is false - remove the output
				toRemove = append(toRemove, outName)
			}
		}
	}

	// Remove outputs with false conditions
	for _, outName := range toRemove {
		delete(outputs, outName)
	}
}

// ResolveConditionsAndFunctions resolves both conditions and functions in the template
func ResolveConditionsAndFunctions(template map[string]interface{}, params map[string]interface{}) map[string]interface{} {
	// Deep copy template to avoid modifying the original
	result := deepCopy(template).(map[string]interface{})

	// Extract resolved parameter values from the Parameters section
	resolvedParams := extractResolvedParams(result)

	// Merge with explicit params
	allParams := make(map[string]interface{})
	for k, v := range params {
		allParams[k] = v
	}
	for k, v := range resolvedParams {
		if _, exists := allParams[k]; !exists {
			allParams[k] = v
		}
	}

	// Step 1: Resolve conditions
	conditions, err := resolveConditions(result, allParams)
	if err != nil {
		// Log the error for debugging
		// If we can't resolve conditions, continue without them
		// This allows templates without conditions to work
		conditions = make(map[string]bool)
		// Keep Conditions section as-is if resolution failed
	} else {
		// Successfully resolved - remove Conditions section from output
		delete(result, "Conditions")
	}

	// Step 2: Add resolved conditions to params (for Fn::If to access)
	for condName, condValue := range conditions {
		allParams[condName] = condValue
	}

	// Step 3: Apply conditions to resources and outputs
	applyConditionsToResources(result, conditions)
	applyConditionsToOutputs(result, conditions)

	// Step 4: Resolve functions
	resolved, err := resolveValue(result, allParams, result)
	if err != nil {
		// Log error but continue with original template
		return result
	}

	return resolved.(map[string]interface{})
}
