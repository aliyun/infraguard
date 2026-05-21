resource "alicloud_alikafka_instance" "compliant" {
  name          = "test-kafka"
  partition_num = 50
  disk_type     = 1
  disk_size     = 500
  deploy_type   = 4
  io_max        = 20
  vswitch_id    = "vsw-123456"
  kms_key_id    = "kms-key-123456"
}
