resource "alicloud_fc_trigger" "violation" {
  name   = "test-trigger"
  type   = "http"
  config = "{\"authType\":\"anonymous\",\"methods\":[\"GET\",\"POST\"]}"
}
