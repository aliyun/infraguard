package funcs

// Mock functions for testing
func mockResolveValue(value interface{}, params map[string]interface{}, template map[string]interface{}) (interface{}, error) {
	return value, nil
}

func mockIsFunction(value interface{}) bool {
	return false
}
