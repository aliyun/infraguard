resource "alicloud_cs_managed_kubernetes" "private_endpoint" {
  name    = "my-ack-cluster"
  version = "1.28.3-aliyun.1"

  worker_vswitch_ids             = ["vsw-aaa", "vsw-bbb", "vsw-ccc"]
  endpoint_public_access_enabled = false
}
