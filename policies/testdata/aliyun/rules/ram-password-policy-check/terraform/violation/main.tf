resource "alicloud_ram_account_password_policy" "weak" {
  minimum_password_length      = 6
  require_lowercase_characters = false
  require_uppercase_characters = false
  require_numbers              = false
  require_symbols              = false
}
