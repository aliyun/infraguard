resource "alicloud_ram_access_key" "inactive" {
  user_name   = "test-user"
  status      = "Inactive"
  secret_file = "/tmp/ak.txt"
}
