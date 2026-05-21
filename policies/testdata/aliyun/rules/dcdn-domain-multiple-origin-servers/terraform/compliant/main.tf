resource "alicloud_dcdn_domain" "multi_origin" {
  domain_name = "dcdn.example.com"
  scope       = "overseas"

  sources {
    content  = "1.1.1.1"
    port     = 80
    priority = 20
    type     = "ipaddr"
    weight   = 10
  }

  sources {
    content  = "2.2.2.2"
    port     = 80
    priority = 20
    type     = "ipaddr"
    weight   = 10
  }
}
