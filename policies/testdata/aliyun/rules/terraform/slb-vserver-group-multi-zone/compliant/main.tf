resource "alicloud_slb_server_group" "multi_zone" {
  load_balancer_id = "lb-abc123"
  name             = "my-vserver-group"

  servers {
    server_ids = ["i-abc123"]
    port       = 80
    weight     = 100
  }

  servers {
    server_ids = ["i-def456"]
    port       = 80
    weight     = 100
  }
}
