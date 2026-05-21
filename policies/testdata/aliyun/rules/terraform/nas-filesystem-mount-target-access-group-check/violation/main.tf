resource "alicloud_nas_mount_target" "default_group" {
  file_system_id    = "xxx"
  access_group_name = "DEFAULT_VPC_GROUP_NAME"
  vswitch_id        = "vsw-xxx"
}
