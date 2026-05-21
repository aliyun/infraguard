resource "alicloud_ram_access_key" "active_key" {
  user_name   = "user1"
  status      = "Active"
  secret_file = "/tmp/ak-secret.txt"
}
