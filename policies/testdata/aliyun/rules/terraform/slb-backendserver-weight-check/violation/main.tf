resource "alicloud_slb_backend_server" "main" {
  load_balancer_id = "lb-123"

  backend_servers {
    server_id = "i-abc123"
    weight    = 0
  }

  backend_servers {
    server_id = "i-def456"
    weight    = 0
  }
}
