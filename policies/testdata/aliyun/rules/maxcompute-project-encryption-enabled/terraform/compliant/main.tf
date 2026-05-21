resource "alicloud_maxcompute_project" "compliant" {
  project_name      = "test_project"
  default_quota     = "default"
  encryption_enable = true
}
