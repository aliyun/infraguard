resource "alicloud_adb_db_cluster_lake_version" "single_zone" {
  db_cluster_version = "5.0"
  vpc_id             = "vpc-xxx"
  vswitch_id         = "vsw-xxx"
  zone_id            = "cn-hangzhou-h"
  compute_resource   = "16ACU"
  storage_resource   = "0ACU"
  payment_type       = "PayAsYouGo"
}
