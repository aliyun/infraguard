resource "alicloud_elasticsearch_instance" "encrypted_node" {
  version      = "7.10_with_X-Pack"
  password     = "Test123!@#"
  vswitch_id   = "vsw-123456"
  payment_type = "PayAsYouGo"

  data_node {
    amount          = 2
    spec            = "elasticsearch.sn1ne.large"
    disk_size       = 20
    disk_type       = "cloud_ssd"
    disk_encryption = true
  }
}
