resource "aws_security_group_rule" "demo_open_ssh" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_s3_bucket_public_access_block" "demo_bucket" {
  bucket                  = "demo-customer-portal"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
