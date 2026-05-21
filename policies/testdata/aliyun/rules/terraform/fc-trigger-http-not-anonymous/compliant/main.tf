resource "alicloud_fc_trigger" "compliant" {
  name   = "test-trigger"
  type   = "http"
  config = "{\"authType\":\"function\",\"methods\":[\"GET\",\"POST\"]}"
}
