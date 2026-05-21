resource "alicloud_oss_bucket" "lrs" {
  bucket          = "cr-lrs-bucket"
  redundancy_type = "LRS"
}

resource "alicloud_cr_ee_instance" "default" {
  payment_type      = "Subscription"
  period            = 1
  renewal_status    = "ManualRenewal"
  instance_type     = "Advanced"
  instance_name     = "cr-lrs"
  custom_oss_bucket = "cr-lrs-bucket"
}
