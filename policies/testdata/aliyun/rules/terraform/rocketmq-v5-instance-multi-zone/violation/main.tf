resource "alicloud_rocketmq_instance" "single" {
  instance_name   = "my-rocketmq"
  sub_series_code = "single_node"
  series_code     = "professional"
}
