resource "alicloud_maxcompute_project" "compliant" {
  project_name  = "test_project"
  default_quota = "default"
  ip_white_list = "10.0.0.0/8,172.16.0.0/12"
}
