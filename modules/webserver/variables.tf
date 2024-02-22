variable "region" {
    type        = string
    description = "region"
}

variable "peer_primary_cidr" {
    type        = string
    description = "Primary CIDR of Peer VPC"
}

variable "primary_cidr" {
    type        = string
    description = "Primary CIDR of the VPC"
}