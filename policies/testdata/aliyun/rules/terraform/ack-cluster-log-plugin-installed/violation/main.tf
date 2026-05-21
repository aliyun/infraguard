resource "alicloud_cs_managed_kubernetes" "no_log_plugin" {
  name    = "my-ack-cluster"
  version = "1.28.3-aliyun.1"

  worker_vswitch_ids = ["vsw-aaa", "vsw-bbb", "vsw-ccc"]

  addons {
    name = "nginx-ingress-controller"
  }

  addons {
    name = "csi-plugin"
  }
}
