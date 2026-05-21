resource "alicloud_oss_bucket" "zrs" {
  bucket          = "cr-zrs-bucket"
  redundancy_type = "ZRS"
}

resource "alicloud_cr_ee_instance" "default" {
  payment_type      = "Subscription"
  period            = 1
  renewal_status    = "ManualRenewal"
  instance_type     = "Advanced"
  instance_name     = "cr-zrs"
  custom_oss_bucket = "cr-zrs-bucket"
}
