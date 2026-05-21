resource "alicloud_cs_managed_kubernetes" "single_zone" {
  name    = "my-ack-cluster"
  version = "1.28.3-aliyun.1"

  worker_vswitch_ids = ["vsw-zone-a", "vsw-zone-b"]
}
