resource "alicloud_cr_ee_repo" "public_repo" {
  instance_id = "cri-xxx"
  namespace   = "my-namespace"
  name        = "my-repo"
  repo_type   = "PUBLIC"
  summary     = "A public repository"
}
