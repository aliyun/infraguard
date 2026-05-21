resource "alicloud_cs_managed_kubernetes" "unsupported" {
  name    = "my-ack-cluster"
  version = "1.20.11-aliyun.1"

  worker_vswitch_ids = ["vsw-aaa", "vsw-bbb", "vsw-ccc"]
}
