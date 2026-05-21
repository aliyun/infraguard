resource "alicloud_nas_access_rule" "restricted" {
  access_group_name = "my-access-group"
  source_cidr_ip    = "10.0.0.0/8"
  rw_access_type    = "RDWR"
  user_access_type  = "no_squash"
  priority          = 1
}
