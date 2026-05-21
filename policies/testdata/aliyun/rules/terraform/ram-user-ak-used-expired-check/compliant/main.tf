resource "alicloud_ram_access_key" "active" {
  user_name   = "test-user"
  status      = "Active"
  secret_file = "/tmp/ak.txt"
}
