resource "alicloud_ram_access_key" "properly_stored" {
  user_name   = "user1"
  status      = "Active"
  secret_file = "/tmp/ak-secret.txt"
}
