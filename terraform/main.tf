terraform {
  required_version = ">= 1.5.0"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "overlap_audit_bucket" {
  type    = string
  default = "cidr-overlap-resolution-audit"
}

output "aws_region" {
  value = var.aws_region
}

output "overlap_audit_bucket" {
  value = var.overlap_audit_bucket
}
