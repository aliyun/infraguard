resource "alicloud_bastionhost_instance" "manual_renewal" {
  description        = "tf-example"
  license_code       = "bhah_ent_50_asset"
  plan_code          = "cloudbastion_ha"
  storage            = "5"
  bandwidth          = "5"
  period             = 1
  renewal_status     = "ManualRenewal"
  vswitch_id         = "vsw-123456"
  security_group_ids = ["sg-123456"]
}
