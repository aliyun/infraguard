resource "alicloud_eci_container_group" "safe_env" {
  container_group_name = "safe-eci"
  vswitch_id           = "vsw-123456"
  security_group_id    = "sg-123456"

  containers {
    name  = "app"
    image = "nginx:latest"

    environment_vars {
      key   = "APP_ENV"
      value = "production"
    }
  }
}
