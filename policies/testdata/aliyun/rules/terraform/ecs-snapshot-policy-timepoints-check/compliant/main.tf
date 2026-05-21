resource "alicloud_ecs_auto_snapshot_policy" "off_peak" {
  name            = "off-peak-policy"
  repeat_weekdays = [1, 2, 3, 4, 5]
  time_points     = [2, 3, 4, 5]
  retention_days  = 30
}
