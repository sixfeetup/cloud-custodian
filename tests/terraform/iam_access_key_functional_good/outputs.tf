# Output values for use in tests
output "test_user_1_name" {
  value = aws_iam_user.test_user_1.name
}

output "test_user_2_name" {
  value = aws_iam_user.test_user_2.name
}

output "test_user_1_arn" {
  value = aws_iam_user.test_user_1.arn
}

output "test_user_2_arn" {
  value = aws_iam_user.test_user_2.arn
}

output "user_1_key_1_id" {
  value = aws_iam_access_key.user_1_key_1.id
}

output "user_1_key_2_id" {
  value = aws_iam_access_key.user_1_key_2.id
}

output "user_2_key_1_id" {
  value = aws_iam_access_key.user_2_key_1.id
}

output "user_1_key_1_status" {
  value = aws_iam_access_key.user_1_key_1.status
}

output "user_1_key_2_status" {
  value = aws_iam_access_key.user_1_key_2.status
}

output "user_2_key_1_status" {
  value = aws_iam_access_key.user_2_key_1.status
}
