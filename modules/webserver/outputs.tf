output "vpc_id" {
    description = "VPC ID"
    value       = module.vpc.vpc_id
}

output "route_table_id" {
    description = "List of IDs of private route tables"
    value       = module.vpc.private_route_table_ids
}

output "webserver_ip" {
    description = "IP address of webserver"
    value       = aws_instance.web.private_ip
}

output "webserver_dns_name" {
    description = "private DNS name of webserver"
    value       = aws_instance.web.private_dns
}