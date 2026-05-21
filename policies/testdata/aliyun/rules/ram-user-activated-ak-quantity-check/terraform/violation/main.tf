resource "alicloud_ram_access_key" "inactive_key" {
  user_name   = "user1"
  status      = "Inactive"
  secret_file = "/tmp/ak-secret.txt"
}
