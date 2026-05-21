resource "alicloud_cs_managed_kubernetes" "not_latest" {
  name    = "my-ack-cluster"
  version = "1.30.1-aliyun.1"

  worker_vswitch_ids = ["vsw-aaa", "vsw-bbb", "vsw-ccc"]
}
