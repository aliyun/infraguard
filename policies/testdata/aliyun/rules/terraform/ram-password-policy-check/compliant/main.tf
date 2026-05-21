resource "alicloud_ram_account_password_policy" "strong" {
  minimum_password_length      = 12
  require_lowercase_characters = true
  require_uppercase_characters = true
  require_numbers              = true
  require_symbols              = true
  max_password_age             = 90
}
