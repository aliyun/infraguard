resource "alicloud_elasticsearch_instance" "deprecated_version" {
  version      = "6.3_with_X-Pack"
  password     = "Test123!@#"
  vswitch_id   = "vsw-123456"
  payment_type = "PayAsYouGo"

  data_node {
    amount    = 3
    spec      = "elasticsearch.sn1ne.large"
    disk_size = 20
    disk_type = "cloud_ssd"
  }
}
