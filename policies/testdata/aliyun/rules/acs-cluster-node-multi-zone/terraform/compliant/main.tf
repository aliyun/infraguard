resource "alicloud_cs_managed_kubernetes" "multi_zone" {
  name    = "my-acs-cluster"
  version = "1.28.3-aliyun.1"

  worker_vswitch_ids = ["vsw-zone-a", "vsw-zone-b", "vsw-zone-c"]
}
