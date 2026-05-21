package infraguard.helpers.terraform

import rego.v1

resources_by_type(resource_type) := resources if {
	resources := input.resources[resource_type]
}

has_resource_type(resource_type) if {
	input.resources[resource_type]
}

get_attribute(resource, attr, default_value) := value if {
	value := resource[attr]
	value != null
} else := default_value

is_unknown(value) if {
	value == "<unknown>"
}
