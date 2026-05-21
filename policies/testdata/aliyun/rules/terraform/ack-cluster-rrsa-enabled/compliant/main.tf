resource "alicloud_cs_managed_kubernetes" "rrsa_enabled" {
  name    = "my-ack-cluster"
  version = "1.28.3-aliyun.1"

  worker_vswitch_ids = ["vsw-aaa", "vsw-bbb", "vsw-ccc"]
  enable_rrsa        = true
}
