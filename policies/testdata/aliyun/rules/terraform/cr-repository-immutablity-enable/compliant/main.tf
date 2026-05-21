resource "alicloud_cr_ee_repo" "default" {
  instance_id      = "cri-compliant"
  namespace        = "prod"
  name             = "app"
  repo_type        = "PRIVATE"
  summary          = "Production app"
  tag_immutability = true
}
