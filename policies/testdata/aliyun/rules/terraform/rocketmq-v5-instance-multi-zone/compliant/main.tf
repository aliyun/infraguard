resource "alicloud_rocketmq_instance" "ha" {
  instance_name   = "my-rocketmq"
  sub_series_code = "cluster_ha"
  series_code     = "professional"
}
