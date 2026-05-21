resource "alicloud_eci_container_group" "sensitive_env" {
  container_group_name = "unsafe-eci"
  vswitch_id           = "vsw-123456"
  security_group_id    = "sg-123456"

  containers {
    name  = "app"
    image = "nginx:latest"

    environment_vars {
      key   = "ACCESS_KEY_ID"
      value = "example-access-key"
    }
  }
}
