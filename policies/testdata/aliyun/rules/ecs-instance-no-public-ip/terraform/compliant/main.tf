resource "alicloud_instance" "web" {
  instance_type              = "ecs.s6-c1m1.small"
  image_id                   = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  internet_max_bandwidth_out = 0
  security_groups            = ["sg-xxx"]
  vswitch_id                 = "vsw-xxx"
}
