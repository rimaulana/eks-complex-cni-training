data "aws_availability_zones" "available" {}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      # This requires the awscli to be installed locally where Terraform is executed
      args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

provider "kubectl" {
  apply_retry_count      = 5
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

locals {
  name      = basename(path.cwd)
  region    = var.region
  azs       = slice(data.aws_availability_zones.available.names, 0, 3)
  tags      = var.tags
  multus_start_range  = cidrhost(cidrsubnet(var.multus_cidrs[var.selector], 1, 1),0)
  multus_end_range    = cidrhost(var.multus_cidrs[var.selector], -2)
  multus_def_gateway  = cidrhost(var.multus_cidrs[var.selector], 1)
}

data "aws_ami" "eks_default" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amazon-eks-node-${var.cluster_version}-v*"]
  }
}
################################################################################
# Cluster
################################################################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.2"

  cluster_name                   = var.cluster_name
  cluster_version                = var.cluster_version
  cluster_endpoint_public_access = true

  vpc_id     = var.vpc_id
  control_plane_subnet_ids = var.control_plane_subnet_ids
  
  authentication_mode = "API_AND_CONFIG_MAP"
  enable_cluster_creator_admin_permissions = true

  tags = local.tags
}

resource "aws_security_group_rule" "vpce_rule" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = var.vpce_sg_id
  source_security_group_id  = module.eks.node_security_group_id
}

resource "aws_security_group" "self_managed_node_security_group" {
  name        = "${var.cluster_name}-self-managed-node-sg"
  description = "Self managed node security group"
  vpc_id      = var.vpc_id
  
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  
  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    security_groups  = [module.eks.cluster_security_group_id]
    self             = true
  }

  tags = local.tags
}

resource "aws_security_group" "eni_security_group" {
  description = "ENI Security Group"
  vpc_id      = var.vpc_id

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  
  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    security_groups  = [aws_security_group.self_managed_node_security_group.id,module.eks.cluster_security_group_id]
    self             = true
  }

  tags = local.tags
}

resource "aws_security_group_rule" "control_plane_security_group_rule_1" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = module.eks.cluster_security_group_id
  source_security_group_id  = aws_security_group.self_managed_node_security_group.id
}

resource "aws_security_group_rule" "control_plane_security_group_rule_2" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = module.eks.cluster_security_group_id
  source_security_group_id  = aws_security_group.eni_security_group.id
}

resource "aws_security_group_rule" "node_security_group_rule_1" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.self_managed_node_security_group.id
  source_security_group_id  = aws_security_group.eni_security_group.id
}

################################################################################
# IRSA for EKS Managed Addons
################################################################################
data "aws_iam_policy_document" "vpc_cni_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(module.eks.oidc_provider_arn, "/^(.*provider/)/", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [module.eks.oidc_provider_arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "vpc_cni_role" {
  assume_role_policy = data.aws_iam_policy_document.vpc_cni_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "vpc_cni_role_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.vpc_cni_role.name
}

################################################################################
# EKS Blueprints Addons
################################################################################

module "eks_blueprints_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"
  version = "~> 1.0"

  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint
  cluster_version   = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn
  
  # create_delay_dependencies = [for prof in module.eks.self_managed_node_groups : prof.autoscaling_group_arn]

  # EKS Add-ons
  eks_addons = {
    vpc-cni    = {
      most_recent    = true # To ensure access to the latest settings provided
      service_account_role_arn = aws_iam_role.vpc_cni_role.arn
      configuration_values = jsonencode({
        env = {
          WARM_IP_TARGET        = "1"
          MINIMUM_IP_TARGET     = "5"
          ENI_CONFIG_LABEL_DEF  = "failure-domain.beta.kubernetes.io/zone"
          AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG    = "true"
          AWS_VPC_K8S_CNI_EXTERNALSNAT  = "true"
        }
      })
    }
    kube-proxy = {
      most_recent    = true
    }
  }
  tags = local.tags
}

resource "aws_iam_role" "self_managed_node_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "ec2.amazonaws.com"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  ]
}

resource "aws_iam_instance_profile" "self_managed_node_profile" {
  role = aws_iam_role.self_managed_node_role.name
}

module "self_managed_node_group" {
  source = "terraform-aws-modules/eks/aws//modules/self-managed-node-group"

  name                = "multus-self-mng"
  cluster_name        = module.eks.cluster_name
  cluster_version     = module.eks.cluster_version
  cluster_endpoint    = module.eks.cluster_endpoint
  cluster_auth_base64 = module.eks.cluster_certificate_authority_data
  create_access_entry = true
  create_iam_instance_profile = false
  iam_instance_profile_arn = aws_iam_instance_profile.self_managed_node_profile.arn
  iam_role_arn        = aws_iam_role.self_managed_node_role.arn

  subnet_ids = [var.node_subnet_ids[var.selector]]

  // The following variables are necessary if you decide to use the module outside of the parent EKS module context.
  // Without it, the security groups of the nodes are empty and thus won't join the cluster.
  vpc_security_group_ids = [
    aws_security_group.self_managed_node_security_group.id
  ]

  min_size     = 0
  max_size     = 10
  desired_size = 0
  
  pre_bootstrap_user_data = <<-EOT
    echo "net.ipv4.conf.default.rp_filter = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp_filter = 0" | tee -a /etc/sysctl.conf
    sudo sysctl -p
    sleep 100
    ls /sys/class/net/ > /tmp/ethList;cat /tmp/ethList |while read line ; do sudo ifconfig $line up; done
    grep eth /tmp/ethList |while read line ; do echo "ifconfig $line up" >> /etc/rc.d/rc.local; done
    systemctl enable rc-local
    chmod +x /etc/rc.d/rc.local
  EOT

  launch_template_name   = "separate-self-mng"
  instance_type          = "m5.large"

  tags = {
    Environment = "dev"
    Terraform   = "true"
  }
}

resource "aws_autoscaling_lifecycle_hook" "launch_hook" {
  name                   = "${var.cluster_name}-launch-lifecyclehook"
  autoscaling_group_name = module.self_managed_node_group.autoscaling_group_name
  default_result         = "ABANDON"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"
}

resource "aws_autoscaling_lifecycle_hook" "terminate_hook" {
  name                   = "${var.cluster_name}-terminate-lifecyclehook"
  autoscaling_group_name = module.self_managed_node_group.autoscaling_group_name
  default_result         = "ABANDON"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
}

module lambda_eni {
  source                = "../../modules/lambda_eni"
  name                  = "${var.cluster_name}-node-ip-management"
  multus_subnets        = var.multus_subnet_ids[var.selector]
  multus_security_groups= var.multus_sg_id
  asg_name              = module.self_managed_node_group.autoscaling_group_name
}

resource "kubectl_manifest" "eni_config_definitions" {
  for_each = { for k, v in local.azs : v => var.cni_subnet_ids[k] }
  apply_only = true
  yaml_body = <<-YAML
    apiVersion: crd.k8s.amazonaws.com/v1alpha1
    kind: ENIConfig
    metadata: 
      name: ${each.key}
    spec: 
      securityGroups: 
      - ${aws_security_group.eni_security_group.id}
      subnet: ${each.value}
  YAML

  depends_on = [
    module.eks
  ]
}

data "kubectl_path_documents" "manifests-directory-yaml" {
  pattern = "${path.module}/manifests/*.yaml"
}
resource "kubectl_manifest" "directory-yaml" {
  apply_only = true
  for_each  = data.kubectl_path_documents.manifests-directory-yaml.manifests
  yaml_body = each.value
  depends_on = [
    module.eks,
    module.eks_blueprints_addons
  ]
}

resource "kubectl_manifest" "multus_nad" {
  depends_on = [
    module.eks,
    kubectl_manifest.directory-yaml
  ]
  apply_only = true
  wait_for_rollout = false
  yaml_body = <<-YAML
    apiVersion: "k8s.cni.cncf.io/v1"
    kind: NetworkAttachmentDefinition
    metadata:
      name: ipvlan-multus
    spec:
      config: '{
                "cniVersion": "0.3.1",
                "type": "ipvlan",
                "LogFile": "/var/log/multus.log",
                "LogLevel": "debug",
                "name": "ipvlan-multus",
                "mtu": 1500,
                "master": "eth1",
                "ipam": {
                  "type": "whereabouts",
                  "datastore": "kubernetes",
                  "range": "${var.multus_cidrs[var.selector]}",
                  "range_start": "${local.multus_start_range}",
                  "range_end": "${local.multus_end_range}",
                  "gateway": "${local.multus_def_gateway}",
                  "log_file": "/tmp/whereabouts.log",
                  "log_level": "debug"
                }
              }'
  YAML
}
################################################################################
# EKS WORKLOAD
################################################################################

resource "kubectl_manifest" "multus_deployment" {
  apply_only = true
  wait_for_rollout = false
  yaml_body = <<-YAML
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: multus-app
      labels:
        app: multus-sample
    spec:
      replicas: 0
      selector:
        matchLabels:
          app: multus-sample
      template:
        metadata:
          labels:
            app: multus-sample
          annotations:
            k8s.v1.cni.cncf.io/networks: ipvlan-multus
        spec:
          containers:
          - name: app
            env:
            - name: WEB_ADDRESS
              value: ${var.webserver_address}
            image: centos
            command: ["/bin/sh"]
            args: ["-c", "while true; do curl -s -o /dev/null -I --connect-timeout 5 -w \"%%{http_code}\\n\" http://$WEB_ADDRESS; sleep 5; done"]
          - name: aws-ip-mgmt
            image: public.ecr.aws/rimaulana/aws-ip-manager:0.1
            imagePullPolicy: IfNotPresent
            args: [/bin/sh, -c, '/app/script.sh sidecar']
  YAML

  depends_on = [
    module.eks
  ]
}