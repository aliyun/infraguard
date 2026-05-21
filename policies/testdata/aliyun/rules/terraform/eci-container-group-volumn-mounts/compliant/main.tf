resource "alicloud_eci_container_group" "with_volume" {
  container_group_name = "safe-eci"
  vswitch_id           = "vsw-123456"
  security_group_id    = "sg-123456"

  containers {
    name  = "app"
    image = "nginx:latest"

    volume_mounts {
      name       = "data"
      mount_path = "/data"
    }
  }

  volumes {
    name = "data"
    type = "EmptyDirVolume"
  }
}
