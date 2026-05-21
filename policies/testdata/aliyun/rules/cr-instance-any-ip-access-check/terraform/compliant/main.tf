resource "alicloud_cr_ee_instance" "default" {
  payment_type   = "Subscription"
  period         = 1
  renewal_status = "ManualRenewal"
  instance_type  = "Advanced"
  instance_name  = "cr-compliant"
}

resource "alicloud_cr_endpoint_acl_policy" "restricted" {
  instance_id   = "cri-compliant"
  entry         = "10.0.0.0/8"
  endpoint_type = "internet"
  module_name   = "Registry"
}
