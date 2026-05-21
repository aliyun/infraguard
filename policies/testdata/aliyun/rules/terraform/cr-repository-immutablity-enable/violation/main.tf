resource "alicloud_cr_ee_repo" "default" {
  instance_id      = "cri-violation"
  namespace        = "prod"
  name             = "app"
  repo_type        = "PRIVATE"
  summary          = "Production app"
  tag_immutability = false
}
