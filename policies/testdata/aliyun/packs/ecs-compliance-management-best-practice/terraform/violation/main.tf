resource "alicloud_instance" "no_protection" {
  instance_type        = "ecs.g6.large"
  image_id             = "ubuntu_22_04_x64_20G_alibase_20230815.vhd"
  instance_charge_type = "PostPaid"
  vswitch_id           = "vsw-12345"
  security_groups      = ["sg-12345"]
  deletion_protection  = false
}
