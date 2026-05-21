resource "alicloud_elasticsearch_instance" "unencrypted" {
  version        = "7.10_with_X-Pack"
  password       = "Test123!@#"
  vswitch_id     = "vsw-123456"
  payment_type   = "PayAsYouGo"
  zone_count     = 2
  private_whitelist = ["10.0.0.0/8"]

  data_node {
    amount          = 3
    spec            = "elasticsearch.sn1ne.large"
    disk_size       = 20
    disk_type       = "cloud_ssd"
    disk_encryption = false
  }
}
