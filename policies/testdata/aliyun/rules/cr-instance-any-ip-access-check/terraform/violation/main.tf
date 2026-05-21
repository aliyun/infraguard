resource "alicloud_cr_ee_instance" "default" {
  payment_type   = "Subscription"
  period         = 1
  renewal_status = "ManualRenewal"
  instance_type  = "Advanced"
  instance_name  = "cr-violation"
}

resource "alicloud_cr_endpoint_acl_policy" "any_ip" {
  instance_id   = "cri-violation"
  entry         = "0.0.0.0/0"
  endpoint_type = "internet"
  module_name   = "Registry"
}
