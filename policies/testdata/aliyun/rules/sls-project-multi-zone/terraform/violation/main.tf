resource "alicloud_log_project" "lrs" {
  name                 = "my-project"
  description          = "LRS project"
  data_redundancy_type = "LRS"
}
