resource "alicloud_slb_listener" "https" {
  load_balancer_id  = "lb-123"
  frontend_port     = 443
  protocol          = "https"
  tls_cipher_policy = "tls_cipher_policy_1_0"
}
