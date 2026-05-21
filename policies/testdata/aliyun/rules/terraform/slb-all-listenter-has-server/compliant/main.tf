resource "alicloud_slb_load_balancer" "main" {
  load_balancer_name = "my-slb"
  address_type       = "internet"
}

resource "alicloud_slb_backend_server" "main" {
  load_balancer_id = "lb-123"

  backend_servers {
    server_id = "i-abc123"
    weight    = 100
  }
}
