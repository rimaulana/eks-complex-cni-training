provider "aws" {
  region = var.region
}

data "aws_availability_zones" "available" {}

data "aws_ami" "amazon-linux-2" {
 most_recent = true


 filter {
   name   = "owner-alias"
   values = ["amazon"]
 }


 filter {
   name   = "name"
   values = ["amzn2-ami-hvm*"]
 }
}

locals {
  name     = basename(path.cwd)
  region   = "us-east-1"

  primary_cidr   = var.primary_cidr
  
  azs      = slice(data.aws_availability_zones.available.names, 0, 2)

  tags = {
    blueprint  = local.name
    "auto-delete" = "no"
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name                  = local.name
  cidr                  = local.primary_cidr
  azs                   = local.azs
  private_subnets       = [for k, v in local.azs : cidrsubnet(local.primary_cidr, 2, k)]
  public_subnets        = [for k, v in local.azs : cidrsubnet(local.primary_cidr, 2, k + 2)]
  
  enable_nat_gateway    = true
  single_nat_gateway    = true

  tags = local.tags
}

resource "aws_security_group" "web_security_group" {
  name        = "web_security_group"
  description = "Web Server Security Group"
  vpc_id      = module.vpc.vpc_id
  
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  
  ingress {
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    self             = true
    cidr_blocks      = [var.peer_primary_cidr]
  }

  tags = local.tags
}

resource "aws_iam_role" "web_instance_role" {
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
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  ]
}

resource "aws_iam_instance_profile" "web_instance_profile" {
  role = aws_iam_role.web_instance_role.name
}

resource "aws_instance" "web" {
  depends_on = [
    module.vpc.natgw_ids
  ]
  ami             = "${data.aws_ami.amazon-linux-2.id}"
  instance_type   = "t3a.medium"
  subnet_id       = module.vpc.private_subnets[0]
  vpc_security_group_ids = [aws_security_group.web_security_group.id]
  iam_instance_profile = aws_iam_instance_profile.web_instance_profile.name
  user_data = <<-EOT
    #!/bin/bash
    echo "*** Installing apache2"
    sudo yum update -y
    sudo yum install httpd -y
    sudo chmod 777 /var/www/html
    cat << EOF > /var/www/html/index.html
    <!DOCTYPE html>
    <html>
      <head>
        <title>Apache Web Server</title>
      </head>
      <body>
        <h1>Apache Web Server</h1>
        <p>This is a simple HTML web page.</p>
      </body>
    </html>
    EOF
    sudo systemctl enable httpd
    sudo systemctl start httpd
    echo "*** Completed Installing apache2"
  EOT

  tags = {
    Name = "web_instance"
  }

  volume_tags = {
    Name = "web_instance"
  } 
}