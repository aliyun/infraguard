resource "alicloud_cs_managed_kubernetes" "latest" {
  name    = "my-ack-cluster"
  version = "1.35.2-aliyun.1"

  worker_vswitch_ids = ["vsw-aaa", "vsw-bbb", "vsw-ccc"]
}
