resource "alicloud_slb_load_balancer" "prepaid" {
  load_balancer_name = "my-slb"
  address_type       = "internet"
  payment_type       = "Subscription"
  renewal_status     = "AutoRenewal"
}
