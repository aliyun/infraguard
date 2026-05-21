resource "alicloud_cs_managed_kubernetes" "pro_encrypted" {
  name         = "my-ack-pro"
  cluster_spec = "ack.pro.small"
  version      = "1.28.3-aliyun.1"

  worker_vswitch_ids      = ["vsw-aaa", "vsw-bbb", "vsw-ccc"]
  encryption_provider_key = "kms-key-id-12345"
}
