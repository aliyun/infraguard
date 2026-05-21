resource "alicloud_vpc" "default" {
  vpc_name   = "my-vpc"
  cidr_block = "172.16.0.0/12"
}

resource "alicloud_vpc_flow_log" "default" {
  flow_log_name = "my-flow-log"
  resource_id   = "vpc-abc123"
  resource_type = "VPC"
  traffic_type  = "All"
  project_name  = "my-log-project"
  log_store_name = "my-log-store"
}
