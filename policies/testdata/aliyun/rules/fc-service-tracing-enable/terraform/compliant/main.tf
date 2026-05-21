resource "alicloud_fc_service" "compliant" {
  name = "test-service"

  tracing_config {
    type   = "Jaeger"
    params = "http://tracing-analysis.com/adapt_abc123@token_abc123@1234567890_abc123/api/traces"
  }
}
