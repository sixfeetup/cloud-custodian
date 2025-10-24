# Output values for use in tests
output "test_user_empty_name" {
  value = aws_iam_user.test_user_empty.name
}

output "test_user_empty_arn" {
  value = aws_iam_user.test_user_empty.arn
}
