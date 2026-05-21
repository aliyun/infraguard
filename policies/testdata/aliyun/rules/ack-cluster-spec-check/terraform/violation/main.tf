resource "alicloud_cs_managed_kubernetes" "standard_cluster" {
  name         = "my-ack-standard"
  cluster_spec = "ack.standard"
  version      = "1.28.3-aliyun.1"

  worker_vswitch_ids = ["vsw-aaa", "vsw-bbb", "vsw-ccc"]
}
