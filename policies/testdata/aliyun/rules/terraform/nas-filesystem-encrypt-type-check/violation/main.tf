resource "alicloud_nas_file_system" "unencrypted" {
  protocol_type = "NFS"
  storage_type  = "Performance"
}
