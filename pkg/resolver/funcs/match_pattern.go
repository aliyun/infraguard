package funcs

import (
	"fmt"
	"regexp"
	"sync"
)

// Global regex cache for FnMatchPattern
var (
	regexCache   = make(map[string]*regexp.Regexp)
	regexCacheMu sync.RWMutex
)

// getCompiledRegex returns a cached compiled regex or compiles and caches it
func getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	// Try read lock first (common case)
	regexCacheMu.RLock()
	if re, exists := regexCache[pattern]; exists {
		regexCacheMu.RUnlock()
		return re, nil
	}
	regexCacheMu.RUnlock()

	// Compile with write lock
	regexCacheMu.Lock()
	defer regexCacheMu.Unlock()

	// Double-check after acquiring write lock
	if re, exists := regexCache[pattern]; exists {
		return re, nil
	}

	// Compile and cache
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCache[pattern] = re
	return re, nil
}

// FnMatchPattern checks if a string matches a regular expression pattern
// Fn::MatchPattern: ["^hello.*", "hello world"] => true
// Fn::MatchPattern: ["^hello.*", "goodbye world"] => false
func FnMatchPattern(value interface{}, params map[string]interface{}, template map[string]interface{}, resolveValue func(interface{}, map[string]interface{}, map[string]interface{}) (interface{}, error), isFunction func(interface{}) bool) (interface{}, error) {
	arr, ok := value.([]interface{})
	if !ok || len(arr) != 2 {
		return nil, fmt.Errorf("Fn::MatchPattern requires an array of [pattern, string]")
	}

	// Resolve pattern
	patternResolved, err := resolveValue(arr[0], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::MatchPattern: error resolving pattern: %w", err)
	}

	pattern, ok := patternResolved.(string)
	if !ok {
		return nil, fmt.Errorf("Fn::MatchPattern: pattern must be a string, got %T", patternResolved)
	}

	// Resolve string
	strResolved, err := resolveValue(arr[1], params, template)
	if err != nil {
		return nil, fmt.Errorf("Fn::MatchPattern: error resolving string: %w", err)
	}

	// If still a function, can't match (not an error, just can't resolve statically)
	if isFunction(strResolved) {
		return map[string]interface{}{"Fn::MatchPattern": value}, nil
	}

	str := fmt.Sprintf("%v", strResolved)

	// Get compiled regex from cache
	re, err := getCompiledRegex(pattern)
	if err != nil {
		return nil, fmt.Errorf("Fn::MatchPattern: invalid regex pattern: %w", err)
	}

	return re.MatchString(str), nil
}
