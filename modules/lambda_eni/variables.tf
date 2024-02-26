variable name {
  type        = string
  description = "The name of the stack"
}

variable multus_subnets {
  type        = string
  description = "Comma separated list of multus subnet to be attached on the node"
}

variable multus_security_groups {
  type        = string
  description = "Comma separated list of multus security group to be attached on the additional eni"
}

variable asg_name {
    type        = string
    description = "The name of the ASG that will tigger the cloudwatch event rule"
}