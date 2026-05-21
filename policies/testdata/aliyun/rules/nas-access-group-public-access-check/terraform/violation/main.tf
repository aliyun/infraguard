resource "alicloud_nas_access_rule" "public" {
  access_group_name = "my-access-group"
  source_cidr_ip    = "0.0.0.0/0"
  rw_access_type    = "RDWR"
  user_access_type  = "no_squash"
  priority          = 1
}
