resource "aws_security_group_rule" "db" { cidr_blocks = ["0.0.0.0/0"] from_port = 5432 }
