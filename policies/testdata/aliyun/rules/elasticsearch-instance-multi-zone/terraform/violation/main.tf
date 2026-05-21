resource "alicloud_elasticsearch_instance" "single_zone" {
  version      = "7.10_with_X-Pack"
  password     = "Test123!@#"
  vswitch_id   = "vsw-123456"
  payment_type = "PayAsYouGo"
  zone_count   = 1

  data_node {
    amount    = 3
    spec      = "elasticsearch.sn1ne.large"
    disk_size = 20
    disk_type = "cloud_ssd"
  }
}
