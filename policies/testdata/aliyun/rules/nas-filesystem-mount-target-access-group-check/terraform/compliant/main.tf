resource "alicloud_nas_mount_target" "custom_group" {
  file_system_id    = "xxx"
  access_group_name = "my-custom-group"
  vswitch_id        = "vsw-xxx"
}
