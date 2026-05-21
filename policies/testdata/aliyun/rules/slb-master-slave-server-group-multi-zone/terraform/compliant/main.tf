resource "alicloud_slb_master_slave_server_group" "multi_zone" {
  load_balancer_id = "lb-abc123"
  name             = "my-group"

  servers {
    server_id = "i-abc123"
    port      = 80
    weight    = 100
  }

  servers {
    server_id = "i-def456"
    port      = 80
    weight    = 100
  }
}
