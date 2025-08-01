# Terraform configuration for EntraID Conditional Access Policy testing
# Creates test conditional access policies for Cloud Custodian policy testing

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

# Get available domains
data "azuread_domains" "current" {
  only_initial = false
}

# Use the first available domain for user principal names
locals {
  domain_name = data.azuread_domains.current.domains[0].domain_name
}

# Get all users to use in policy assignments
data "azuread_users" "all_users" {
  return_all = true
}

# Create test users for policy assignments
resource "azuread_user" "test_policy_user" {
  user_principal_name   = "c7n-policy-test-${random_string.suffix.result}@${local.domain_name}"
  display_name          = "C7N Policy Test User"
  mail_nickname        = "c7n-policy-test-${random_string.suffix.result}"
  password             = "P@ssw0rd123!"
  force_password_change = false
  account_enabled      = true
  
  lifecycle {
    ignore_changes = [password]
  }
}

# Test Conditional Access Policy 1: Enabled MFA policy for all users
resource "azuread_conditional_access_policy" "test_mfa_all_users" {
  display_name = "C7N Test - Require MFA for All Users ${random_string.suffix.result}"
  state        = "enabled"

  conditions {
    users {
      included_users = ["All"]
      excluded_users = []
    }

    applications {
      included_applications = ["All"]
      excluded_applications = []
    }

    locations {
      included_locations = ["All"]
      excluded_locations = []
    }

    platforms {
      included_platforms = ["all"]
      excluded_platforms = []
    }

    client_app_types = ["all"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }

  session_controls {
    application_enforced_restrictions_enabled = false
  }
}

# Test Conditional Access Policy 2: Disabled policy (for testing disabled policy detection)
resource "azuread_conditional_access_policy" "test_disabled_policy" {
  display_name = "C7N Test - Disabled Policy ${random_string.suffix.result}"
  state        = "disabled"

  conditions {
    users {
      included_users = [azuread_user.test_policy_user.id]
      excluded_users = []
    }

    applications {
      included_applications = ["All"]
      excluded_applications = []
    }

    locations {
      included_locations = ["All"]
      excluded_locations = []
    }

    platforms {
      included_platforms = ["all"]
      excluded_platforms = []
    }

    client_app_types = ["all"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }

  session_controls {
    application_enforced_restrictions_enabled = false
  }
}

# Test Conditional Access Policy 3: Report-only policy (for testing report-only detection)
resource "azuread_conditional_access_policy" "test_report_only_policy" {
  display_name = "C7N Test - Report Only Policy ${random_string.suffix.result}"
  state        = "enabledForReportingButNotEnforced"

  conditions {
    users {
      included_users = ["All"]
      excluded_users = []
    }

    applications {
      included_applications = ["All"]
      excluded_applications = []
    }

    locations {
      included_locations = ["All"]
      excluded_locations = []
    }

    platforms {
      included_platforms = ["all"]
      excluded_platforms = []
    }

    client_app_types = ["all"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["compliantDevice"]
  }

  session_controls {
    application_enforced_restrictions_enabled = false
  }
}

# Test Conditional Access Policy 4: Block legacy authentication
resource "azuread_conditional_access_policy" "test_block_legacy_auth" {
  display_name = "C7N Test - Block Legacy Authentication ${random_string.suffix.result}"
  state        = "enabled"

  conditions {
    users {
      included_users = ["All"]
      excluded_users = []
    }

    applications {
      included_applications = ["All"]
      excluded_applications = []
    }

    locations {
      included_locations = ["All"]
      excluded_locations = []
    }

    platforms {
      included_platforms = ["all"]
      excluded_platforms = []
    }

    client_app_types = ["exchangeActiveSync", "other"]
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }

  session_controls {
    application_enforced_restrictions_enabled = false
  }
}

# Outputs for pytest-terraform to use
output "test_mfa_all_users_policy" {
  value = {
    id           = azuread_conditional_access_policy.test_mfa_all_users.id
    display_name = azuread_conditional_access_policy.test_mfa_all_users.display_name
    state        = azuread_conditional_access_policy.test_mfa_all_users.state
    conditions   = {
      users_included    = azuread_conditional_access_policy.test_mfa_all_users.conditions[0].users[0].included_users
      apps_included     = azuread_conditional_access_policy.test_mfa_all_users.conditions[0].applications[0].included_applications
      client_app_types  = azuread_conditional_access_policy.test_mfa_all_users.conditions[0].client_app_types
    }
    grant_controls = {
      operator          = azuread_conditional_access_policy.test_mfa_all_users.grant_controls[0].operator
      built_in_controls = azuread_conditional_access_policy.test_mfa_all_users.grant_controls[0].built_in_controls
    }
  }
}

output "test_disabled_policy" {
  value = {
    id           = azuread_conditional_access_policy.test_disabled_policy.id
    display_name = azuread_conditional_access_policy.test_disabled_policy.display_name
    state        = azuread_conditional_access_policy.test_disabled_policy.state
    conditions   = {
      users_included    = azuread_conditional_access_policy.test_disabled_policy.conditions[0].users[0].included_users
      apps_included     = azuread_conditional_access_policy.test_disabled_policy.conditions[0].applications[0].included_applications
      client_app_types  = azuread_conditional_access_policy.test_disabled_policy.conditions[0].client_app_types
    }
    grant_controls = {
      operator          = azuread_conditional_access_policy.test_disabled_policy.grant_controls[0].operator
      built_in_controls = azuread_conditional_access_policy.test_disabled_policy.grant_controls[0].built_in_controls
    }
  }
}

output "test_report_only_policy" {
  value = {
    id           = azuread_conditional_access_policy.test_report_only_policy.id
    display_name = azuread_conditional_access_policy.test_report_only_policy.display_name
    state        = azuread_conditional_access_policy.test_report_only_policy.state
    conditions   = {
      users_included    = azuread_conditional_access_policy.test_report_only_policy.conditions[0].users[0].included_users
      apps_included     = azuread_conditional_access_policy.test_report_only_policy.conditions[0].applications[0].included_applications
      client_app_types  = azuread_conditional_access_policy.test_report_only_policy.conditions[0].client_app_types
    }
    grant_controls = {
      operator          = azuread_conditional_access_policy.test_report_only_policy.grant_controls[0].operator
      built_in_controls = azuread_conditional_access_policy.test_report_only_policy.grant_controls[0].built_in_controls
    }
  }
}

output "test_block_legacy_auth_policy" {
  value = {
    id           = azuread_conditional_access_policy.test_block_legacy_auth.id
    display_name = azuread_conditional_access_policy.test_block_legacy_auth.display_name
    state        = azuread_conditional_access_policy.test_block_legacy_auth.state
    conditions   = {
      users_included    = azuread_conditional_access_policy.test_block_legacy_auth.conditions[0].users[0].included_users
      apps_included     = azuread_conditional_access_policy.test_block_legacy_auth.conditions[0].applications[0].included_applications
      client_app_types  = azuread_conditional_access_policy.test_block_legacy_auth.conditions[0].client_app_types
    }
    grant_controls = {
      operator          = azuread_conditional_access_policy.test_block_legacy_auth.grant_controls[0].operator
      built_in_controls = azuread_conditional_access_policy.test_block_legacy_auth.grant_controls[0].built_in_controls
    }
  }
}

output "test_policy_user" {
  value = {
    id                    = azuread_user.test_policy_user.id
    object_id            = azuread_user.test_policy_user.object_id
    user_principal_name  = azuread_user.test_policy_user.user_principal_name
    display_name         = azuread_user.test_policy_user.display_name
  }
}