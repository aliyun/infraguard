resource "alicloud_nas_file_system" "encrypted" {
  protocol_type = "NFS"
  storage_type  = "Performance"
  encrypt_type  = 1
}
