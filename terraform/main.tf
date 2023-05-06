provider "aws" {
  region = "us-west-2"
}

locals {
  public_ip = var.public_ip
}

resource "aws_vpc" "this" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "openvpn-vpc"
  }
}

resource "aws_subnet" "this" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "openvpn-subnet"
  }
}

resource "aws_security_group" "this" {
  name        = "openvpn-sg"
  description = "Allow inbound traffic for OpenVPN"
  vpc_id      = aws_vpc.this.id

  ingress {
    from_port   = 1194
    to_port     = 1194
    protocol    = "udp"
    cidr_blocks = ["${local.public_ip}/32"]
  }
}

resource "aws_ecr_repository" "this" {
  name = "openvpn-docker"
}



resource "aws_ecs_task_definition" "this" {
  family                   = "openvpn"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([{
    name  = "openvpn"
    image = aws_ecr_repository.this.repository_url

    essential = true
    cpu       = 256
    memory    = 512

    portMappings = [
      {
        containerPort = 1194
        hostPort      = 1194
        protocol      = "udp"
      }
    ]
  }])
}

resource "aws_ecs_service" "this" {
  name            = "openvpn"
  cluster         = "default"
  task_definition = aws_ecs_task_definition.this.arn
  desired_count = 1
  launch_type   = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.this.id]
    security_groups  = [aws_security_group.this.id]
    assign_public_ip = true
  }

  depends_on = [
    aws_iam_role_policy.ecs_execution_role_policy,
    aws_iam_role_policy.ecs_task_role_policy,
  ]
}

resource "aws_iam_role" "ecs_execution_role" {
  name = "ecs_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_execution_role_policy" {
  name = "ecs_execution_role_policy"
  role = aws_iam_role.ecs_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
  })
}
resource "aws_iam_role" "ecs_task_role" {
  name = "ecs_task_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ecs_task_role_policy" {
  name = "ecs_task_role_policy"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
  })
}
