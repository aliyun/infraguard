resource "alicloud_fc_function" "violation" {
  service     = "my-service"
  name        = "my-function"
  handler     = "index.handler"
  runtime     = "python2.7"
  memory_size = 128
}
