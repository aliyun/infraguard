resource "alicloud_bastionhost_instance" "auto_renewing" {
  description        = "tf-example"
  license_code       = "bhah_ent_50_asset"
  plan_code          = "cloudbastion_ha"
  storage            = "5"
  bandwidth          = "5"
  period             = 1
  renewal_status     = "AutoRenewal"
  renew_period       = 1
  vswitch_id         = "vsw-123456"
  security_group_ids = ["sg-123456"]
}
