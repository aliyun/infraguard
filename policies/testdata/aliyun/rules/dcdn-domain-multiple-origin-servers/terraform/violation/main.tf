resource "alicloud_dcdn_domain" "single_origin" {
  domain_name = "dcdn.example.com"
  scope       = "overseas"

  sources {
    content  = "1.1.1.1"
    port     = 80
    priority = 20
    type     = "ipaddr"
    weight   = 10
  }
}
