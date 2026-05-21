resource "alicloud_kvstore_instance" "cluster" {
  db_instance_name = "my-redis-cluster"
  instance_class   = "redis.cluster.sharding.ce.1g.4db.0rodb.4proxy.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
}

resource "alicloud_kvstore_instance" "sharded" {
  db_instance_name = "my-redis-sharded"
  instance_class   = "redis.master.small.default"
  instance_type    = "Redis"
  vswitch_id       = "vsw-abc123"
  shard_number     = 4
}
