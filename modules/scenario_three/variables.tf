variable "cluster_name" {
    type        = string
    description = "The name of EKS cluster"
}

variable "cluster_version" {
    type        = string
    description = "The Kubernetes version of EKS cluster"
}

variable "region" {
    type        = string
    description = "The region of the cluster"
}

variable "tags" {
  description = "Tags to be attached to the cluster"
  type        = map(any)
}

variable "vpc_id" {
  description = "vpc_id for EKS cluster"
  type        = string
}

variable "node_subnet_ids" {
  description = "subnet ids for worker nodes"
  type        = list(string)
}

variable "cni_subnet_ids" {
  description = "subnet ids for CNI custom networking"
  type        = list(string)
}

variable "multus_subnet_ids" {
  description = "subnet ids for multus ENI"
  type        = list(string)
}

variable "vpce_sg_id" {
  description = "security group for node"
  type        = string
}

variable "multus_sg_id" {
  description = "security group of multus managed eni"
  type        = string
}

variable "control_plane_subnet_ids" {
  description = "subnet ids for EKS control plane"
  type        = list(string)
}

variable "multus_cidrs" {
  description = "CIDR for Multus CNI"
  type        = list(string)
}

variable "selector" {
  description = "Integer to select subnet from range"
  type        = number
}

variable "webserver_address" {
  description = "IP address of target webserver"
  type        = string
}