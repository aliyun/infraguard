resource "alicloud_cs_managed_kubernetes" "outdated_version" {
  name    = "my-ack-cluster"
  version = "1.18"

  worker_vswitch_ids = ["vsw-aaa", "vsw-bbb", "vsw-ccc"]
}
