output "self_managed_autoscaling_group_name" {
    description = "The autoscaling group name"
    value       = module.self_managed_node_group.autoscaling_group_name
}

# output "multus_security_groups" {
#     description = "The autoscaling group name"
#     value       = module.self_managed_node_group.autoscaling_group_name
# }