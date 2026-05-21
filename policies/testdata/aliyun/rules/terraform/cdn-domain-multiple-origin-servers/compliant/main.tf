resource "alicloud_cdn_domain_new" "multi_origin" {
  domain_name = "cdn.example.com"
  cdn_type    = "web"

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
