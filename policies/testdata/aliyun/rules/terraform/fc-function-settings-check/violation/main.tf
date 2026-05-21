resource "alicloud_fc_function" "violation" {
  service     = "my-service"
  name        = "my-function"
  handler     = ""
  runtime     = "python3.10"
  memory_size = 128
}
