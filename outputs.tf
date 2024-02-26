output "asg_name" {
    description = "The scenarios' autoscaling group name"
    value       = [
        module.scenario_one.self_managed_autoscaling_group_name,
        module.scenario_two.self_managed_autoscaling_group_name,
        module.scenario_three.self_managed_autoscaling_group_name
    ]
}

output "region" {
    value   = local.region
}