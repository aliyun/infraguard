resource "alicloud_instance" "web" {
  instance_type                 = "ecs.s6-c1m1.small"
  image_id                      = "ubuntu_22_04_x64_20G_alibase_20230208.vhd"
  security_groups               = ["sg-123456"]
  vswitch_id                    = "vsw-123456"
  internet_max_bandwidth_out    = 0
  instance_charge_type          = "PrePaid"
  auto_renew                    = false
  internet_charge_type          = "PayByTraffic"
  deletion_protection           = true
  security_enhancement_strategy = "Active"
  key_name                      = "kp-123456"
  ram_role_name                 = "ecs-instance-role"
  system_disk_size              = 40

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}
