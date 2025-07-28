# Terraform configuration for EntraID Group testing
# Creates test groups with various configurations for Cloud Custodian policy testing

terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

# Generate random suffix for unique naming
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Get current client configuration
data "azuread_client_config" "current" {}

# Test Security Group 1: Small security group with few members
resource "azuread_group" "test_small_security_group" {
  display_name     = "C7N Test Small Security Group ${random_string.suffix.result}"
  mail_enabled     = false
  security_enabled = true
  description      = "Small security group for Cloud Custodian testing"
  assignable_to_role = false
}

# Test Security Group 2: Large security group (simulate many members)
resource "azuread_group" "test_large_security_group" {
  display_name     = "C7N Test Large Security Group ${random_string.suffix.result}"
  mail_enabled     = false
  security_enabled = true
  description      = "Large security group for Cloud Custodian testing - simulates group with many members"
  assignable_to_role = false
}

# Test Microsoft 365 Group: For testing unified groups
resource "azuread_group" "test_m365_group" {
  display_name     = "C7N Test M365 Group ${random_string.suffix.result}"
  mail_enabled     = true
  security_enabled = false
  mail_nickname    = "c7n-test-m365-${random_string.suffix.result}"
  description      = "Microsoft 365 group for Cloud Custodian testing"
  types            = ["Unified"]
  visibility       = "Private"
}

# Test Distribution Group: For testing mail-enabled groups
resource "azuread_group" "test_distribution_group" {
  display_name     = "C7N Test Distribution Group ${random_string.suffix.result}"
  mail_enabled     = true
  security_enabled = false
  mail_nickname    = "c7n-test-dist-${random_string.suffix.result}"
  description      = "Distribution group for Cloud Custodian testing"
}

# Test Role-Assignable Group: For testing privileged groups
resource "azuread_group" "test_role_assignable_group" {
  display_name     = "C7N Test Role Assignable Group ${random_string.suffix.result}"
  mail_enabled     = false
  security_enabled = true
  description      = "Role-assignable security group for Cloud Custodian testing"
  assignable_to_role = true
}

# Create test users to populate groups
resource "azuread_user" "test_user_1" {
  user_principal_name   = "c7n-test-user1-${random_string.suffix.result}@${data.azuread_client_config.current.tenant_id}"
  display_name          = "C7N Test User 1"
  mail_nickname        = "c7n-test-user1-${random_string.suffix.result}"
  password             = "P@ssw0rd123!"
  force_password_change = false
  account_enabled      = true
  
  lifecycle {
    ignore_changes = [password]
  }
}

resource "azuread_user" "test_user_2" {
  user_principal_name   = "c7n-test-user2-${random_string.suffix.result}@${data.azuread_client_config.current.tenant_id}"
  display_name          = "C7N Test User 2"
  mail_nickname        = "c7n-test-user2-${random_string.suffix.result}"
  password             = "P@ssw0rd123!"
  force_password_change = false
  account_enabled      = true
  
  lifecycle {
    ignore_changes = [password]
  }
}

resource "azuread_user" "test_user_3" {
  user_principal_name   = "c7n-test-user3-${random_string.suffix.result}@${data.azuread_client_config.current.tenant_id}"
  display_name          = "C7N Test User 3"
  mail_nickname        = "c7n-test-user3-${random_string.suffix.result}"
  password             = "P@ssw0rd123!"
  force_password_change = false
  account_enabled      = true
  
  lifecycle {
    ignore_changes = [password]
  }
}

# Add members to small security group (2 members)
resource "azuread_group_member" "small_group_member_1" {
  group_object_id  = azuread_group.test_small_security_group.object_id
  member_object_id = azuread_user.test_user_1.object_id
}

resource "azuread_group_member" "small_group_member_2" {
  group_object_id  = azuread_group.test_small_security_group.object_id
  member_object_id = azuread_user.test_user_2.object_id
}

# Add members to large security group (3 members)  
resource "azuread_group_member" "large_group_member_1" {
  group_object_id  = azuread_group.test_large_security_group.object_id
  member_object_id = azuread_user.test_user_1.object_id
}

resource "azuread_group_member" "large_group_member_2" {
  group_object_id  = azuread_group.test_large_security_group.object_id
  member_object_id = azuread_user.test_user_2.object_id
}

resource "azuread_group_member" "large_group_member_3" {
  group_object_id  = azuread_group.test_large_security_group.object_id
  member_object_id = azuread_user.test_user_3.object_id
}

# Add members to M365 group (1 member)
resource "azuread_group_member" "m365_group_member" {
  group_object_id  = azuread_group.test_m365_group.object_id
  member_object_id = azuread_user.test_user_3.object_id
}

# Add owner to role-assignable group
resource "azuread_group_owner" "role_assignable_owner" {
  group_object_id  = azuread_group.test_role_assignable_group.object_id
  owner_object_id  = azuread_user.test_user_1.object_id
}

# Outputs for pytest-terraform to use
output "test_small_security_group" {
  value = {
    id                 = azuread_group.test_small_security_group.id
    object_id         = azuread_group.test_small_security_group.object_id
    display_name      = azuread_group.test_small_security_group.display_name
    description       = azuread_group.test_small_security_group.description
    mail_enabled      = azuread_group.test_small_security_group.mail_enabled
    security_enabled  = azuread_group.test_small_security_group.security_enabled
    assignable_to_role = azuread_group.test_small_security_group.assignable_to_role
  }
}

output "test_large_security_group" {
  value = {
    id                 = azuread_group.test_large_security_group.id
    object_id         = azuread_group.test_large_security_group.object_id
    display_name      = azuread_group.test_large_security_group.display_name
    description       = azuread_group.test_large_security_group.description
    mail_enabled      = azuread_group.test_large_security_group.mail_enabled
    security_enabled  = azuread_group.test_large_security_group.security_enabled
    assignable_to_role = azuread_group.test_large_security_group.assignable_to_role
  }
}

output "test_m365_group" {
  value = {
    id                 = azuread_group.test_m365_group.id
    object_id         = azuread_group.test_m365_group.object_id
    display_name      = azuread_group.test_m365_group.display_name
    description       = azuread_group.test_m365_group.description
    mail_enabled      = azuread_group.test_m365_group.mail_enabled
    security_enabled  = azuread_group.test_m365_group.security_enabled
    mail_nickname     = azuread_group.test_m365_group.mail_nickname
    types             = azuread_group.test_m365_group.types
    visibility        = azuread_group.test_m365_group.visibility
  }
}

output "test_distribution_group" {
  value = {
    id                 = azuread_group.test_distribution_group.id
    object_id         = azuread_group.test_distribution_group.object_id
    display_name      = azuread_group.test_distribution_group.display_name
    description       = azuread_group.test_distribution_group.description
    mail_enabled      = azuread_group.test_distribution_group.mail_enabled
    security_enabled  = azuread_group.test_distribution_group.security_enabled
    mail_nickname     = azuread_group.test_distribution_group.mail_nickname
  }
}

output "test_role_assignable_group" {
  value = {
    id                 = azuread_group.test_role_assignable_group.id
    object_id         = azuread_group.test_role_assignable_group.object_id
    display_name      = azuread_group.test_role_assignable_group.display_name
    description       = azuread_group.test_role_assignable_group.description
    mail_enabled      = azuread_group.test_role_assignable_group.mail_enabled
    security_enabled  = azuread_group.test_role_assignable_group.security_enabled
    assignable_to_role = azuread_group.test_role_assignable_group.assignable_to_role
  }
}

output "test_users" {
  value = {
    user_1 = {
      id                    = azuread_user.test_user_1.id
      object_id            = azuread_user.test_user_1.object_id
      user_principal_name  = azuread_user.test_user_1.user_principal_name
      display_name         = azuread_user.test_user_1.display_name
    }
    user_2 = {
      id                    = azuread_user.test_user_2.id
      object_id            = azuread_user.test_user_2.object_id
      user_principal_name  = azuread_user.test_user_2.user_principal_name
      display_name         = azuread_user.test_user_2.display_name
    }
    user_3 = {
      id                    = azuread_user.test_user_3.id
      object_id            = azuread_user.test_user_3.object_id
      user_principal_name  = azuread_user.test_user_3.user_principal_name
      display_name         = azuread_user.test_user_3.display_name
    }
  }
}