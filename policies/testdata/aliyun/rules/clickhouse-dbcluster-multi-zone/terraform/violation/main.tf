resource "alicloud_click_house_db_cluster" "basic" {
  category                = "Basic"
  db_cluster_class        = "S8"
  db_cluster_network_type = "vpc"
  db_cluster_version      = "22.8.5.29"
  db_node_group_count     = 1
  db_node_storage         = "100"
  payment_type            = "PayAsYouGo"
  vswitch_id              = "vsw-xxx"
}
