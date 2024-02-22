data "archive_file" "lambda_node_source_zip" {
  type        = "zip"
  source_file = "${path.module}/source/lambda.py"
  output_path = "${path.module}/source/lambda.zip"
}

resource "aws_lambda_function" "lambda_node" {
  function_name = "${var.name}-node-eni-manager"
  description = "Managed secondary ENI for Multus"
  handler = "lambda.lambda_handler"
  environment {
    variables = {
      SubnetIds = var.multus_subnets
      SecGroupIds = var.multus_security_groups
      useStaticIPs = "false"
      ENITags = ""
    }
  }
  role = aws_iam_role.lambda_node_role.arn
  runtime = "python3.8"
  timeout = 120
  memory_size = 256
  filename = "${path.module}/source/lambda.zip"
  source_code_hash = data.archive_file.lambda_node_source_zip.output_base64sha256
}

resource "aws_cloudwatch_event_rule" "asg_event_rule" {
  name = "${var.name}-asg-event-invoker"
  description = "Triggers for ASG lifecyclehook"
  event_pattern = jsonencode({
    source = [
      "aws.autoscaling"
    ]
    detail-type = [
      "EC2 Instance-launch Lifecycle Action",
      "EC2 Instance-terminate Lifecycle Action"
    ]
    detail = {
      AutoScalingGroupName = ["${var.asg_name}"]
    }
  })
}

resource "aws_cloudwatch_event_target" "asg_event_rule_target" {
  rule      = aws_cloudwatch_event_rule.asg_event_rule.name
  target_id = aws_cloudwatch_event_rule.asg_event_rule.name
  arn       = aws_lambda_function.lambda_node.arn
}

resource "aws_lambda_permission" "permission_for_event_to_invoke_lambda_node" {
  statement_id  = "PermissionForEventsToInvokeLambdaNode"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_node.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.asg_event_rule.arn
}

resource "aws_iam_role" "lambda_node_role" {
  name = "${var.name}-lambda-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  path = "/"
  inline_policy {
    name = "LambdaAttach2ndEni"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents"
          ]
          Resource = "arn:aws:logs:*:*:*"
        },
        {
          Effect = "Allow"
          Action = [
            "ec2:CreateNetworkInterface",
            "ec2:DescribeInstances",
            "ec2:UnassignPrivateIpAddresses",
            "ec2:UnassignIpv6Addresses",
            "ec2:AssignPrivateIpAddresses",
            "ec2:AssignIpv6Addresses",
            "ec2:DetachNetworkInterface",
            "ec2:ModifyNetworkInterfaceAttribute",
            "ec2:DescribeSubnets",
            "autoscaling:CompleteLifecycleAction",
            "ec2:DeleteTags",
            "ec2:DescribeNetworkInterfaces",
            "ec2:CreateTags",
            "ec2:DeleteNetworkInterface",
            "ec2:AttachNetworkInterface",
            "autoscaling:DescribeAutoScalingGroups",
            "ec2:TerminateInstances"
          ]
          Resource = "*"
        }
      ]
    })
  }
}