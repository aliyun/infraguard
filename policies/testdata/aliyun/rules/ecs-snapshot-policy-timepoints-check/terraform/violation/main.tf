resource "alicloud_ecs_auto_snapshot_policy" "business_hours" {
  name            = "business-hours-policy"
  repeat_weekdays = [1, 2, 3, 4, 5]
  time_points     = [10, 14, 18]
  retention_days  = 30
}
