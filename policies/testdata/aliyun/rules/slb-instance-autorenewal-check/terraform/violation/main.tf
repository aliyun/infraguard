resource "alicloud_slb_load_balancer" "prepaid_no_renewal" {
  load_balancer_name = "my-slb"
  address_type       = "internet"
  payment_type       = "Subscription"
  renewal_status     = "Normal"
}
