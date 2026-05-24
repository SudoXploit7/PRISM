provider "aws" {
  region = "us-east-1"
}

# 1. Vulnerable Mock Role with Admin privileges (Shadow Admin target)
resource "aws_iam_role" "prism_vulnerable_role" {
  name = "prism-demo-vulnerable-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "*" # Excessively permissive trust relationship
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "vuln_admin_attach" {
  role       = aws_iam_role.prism_vulnerable_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# 2. Vulnerable User with PassRole and Lambda privileges
resource "aws_iam_user" "prism_compromised_user" {
  name = "prism-demo-compromised-user"
}

resource "aws_iam_access_key" "prism_compromised_user_key" {
  user = aws_iam_user.prism_compromised_user.name
}

resource "aws_iam_user_policy" "prism_passrole_abuse" {
  name = "prism-passrole-abuse"
  user = aws_iam_user.prism_compromised_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction"
        ]
        Resource = "*"
      }
    ]
  })
}

# 3. Ransomware Target - S3 Bucket without Versioning or Object Lock
resource "aws_s3_bucket" "prism_ransomware_target" {
  bucket_prefix = "prism-demo-data-target"
}

resource "aws_s3_bucket_public_access_block" "prism_public_access" {
  bucket = aws_s3_bucket.prism_ransomware_target.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "prism_public_bucket" {
  bucket = aws_s3_bucket.prism_ransomware_target.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = [
            "s3:GetObject",
            "s3:ListBucket"
        ]
        Resource  = [
            aws_s3_bucket.prism_ransomware_target.arn,
            "${aws_s3_bucket.prism_ransomware_target.arn}/*"
        ]
      }
    ]
  })
}

output "compromised_user_access_key" {
  value = aws_iam_access_key.prism_compromised_user_key.id
}
output "compromised_user_secret_key" {
  value     = aws_iam_access_key.prism_compromised_user_key.secret
  sensitive = true
}
