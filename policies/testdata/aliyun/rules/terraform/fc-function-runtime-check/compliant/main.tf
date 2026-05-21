resource "alicloud_fc_function" "compliant" {
  service     = "my-service"
  name        = "my-function"
  handler     = "index.handler"
  runtime     = "python3.10"
  memory_size = 128
}
