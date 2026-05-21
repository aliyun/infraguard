resource "alicloud_slb_server_group" "single_server" {
  load_balancer_id = "lb-abc123"
  name             = "my-vserver-group"

  servers {
    server_ids = ["i-abc123"]
    port       = 80
    weight     = 100
  }
}
