package terraform

func convertToOPAInput(result *EvalResult) map[string]interface{} {
	input := map[string]interface{}{
		"format": "terraform",
	}

	resources := make(map[string]interface{})
	for resType, instances := range result.Resources {
		typeMap := make(map[string]interface{})
		for name, attrs := range instances {
			typeMap[name] = attrs
		}
		resources[resType] = typeMap
	}
	input["resources"] = resources

	input["variables"] = result.Variables
	input["locals"] = result.Locals

	dataSources := make(map[string]interface{})
	for dsType, instances := range result.DataSources {
		typeMap := make(map[string]interface{})
		for name, attrs := range instances {
			typeMap[name] = attrs
		}
		dataSources[dsType] = typeMap
	}
	input["data_sources"] = dataSources
	input["outputs"] = result.Outputs

	return input
}
