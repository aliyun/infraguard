resource "alicloud_log_project" "zrs" {
  name                 = "my-project"
  description          = "ZRS project"
  data_redundancy_type = "ZRS"
}
