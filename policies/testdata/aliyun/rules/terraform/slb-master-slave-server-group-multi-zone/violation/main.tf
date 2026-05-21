resource "alicloud_slb_master_slave_server_group" "single_server" {
  load_balancer_id = "lb-abc123"
  name             = "my-group"

  servers {
    server_id = "i-abc123"
    port      = 80
    weight    = 100
  }
}
