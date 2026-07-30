# Setting up to record against a Google Workspace.

This is the one-time setup needed to record the flight data for
`test_workspace.py`. For how the GCP project, Workspace account, service
account and impersonated user fit together, see
`docs/source/gcp/examples/workspace-user-mfa.rst`.

1. Obtain a domain

2. Create a workspace against that domain.
   1. See https://docs.cloud.google.com/identity/docs/how-to/set-up-cloud-identity-admin#sign-up-free
   2. Assuming you aren't a workspace customer, you'll visit
      https://workspace.google.com/gcpidentity/signup?sku=identitybasic
      That will walk you through creating a workspace admin and
      verifying you own the domain by helping you create a TXT record
      that it will read.

      Setting up users, including the admin user, will define email
      addresses. This doesn't make them deliverable.  This process
      won't mess with the domains MX records by default.

3. Create a service account in your dev GCP account (IAM & Admin -> Service Accounts).
   Also define and download a key file that you'll use to authenicate
   with the service account.

   The key file is JSON. Two of its fields are worth knowing:

   - `client_id`: the numeric id you'll paste into the domain-wide
     delegation entry in step 5. (The console also shows it on the service
     account as "Unique ID".)
   - `client_email`: identifies the service account, but is *not* what
     step 5 wants.

   Point `GOOGLE_APPLICATION_CREDENTIALS` at this file.

4. Log onto the workspace at https://admin.google.com

5. In the workspace, go to
   Security > Access and data control > API controls > Manage Domain-Wide Delegation.
   Click "Add new" and enter the service account id (a long string of
   digits) and, for the
   "scope":
   https://www.googleapis.com/auth/admin.directory.user.readonly

6. Enable the workspace API.  In your GCP dev project:
   1. Navigate to APIs & Services.
   2. Select "Library".
   3. Search for Admin SDK API
   4. Select it and click "Enable"

7. Set up test users:

   - test_admin, enable 2sv,
   - test_needno2sv, enable 2sv
   - test_2sv, enable 2sv
   - test_no2sv

   All of these **test** users may be suspended by google overnight. :)
   Just go ahead and suspend them for test consistency.  The tests
   work fine and actiually depend on them being suspended.

   Also enable 2sv on the super admin account, which is good hygiene
   anyway. And, of course, don't suspend it.

8. Turn on 2sv enforcement on the root organization unit.

   **IMPORTANT! Set up 2sv on the super admin acount first!**

9. Assign some admin role to test_admin. It doesn't matter which
   one. Whatever is first in the list is fine. :)

10. Create a sub-organization with 2sv not enforced and add test_needno2sv to it.

## Recording

Temporarily change `replay_flight_data` to `record_flight_data` in the test
you want to record, then:

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa-key.json
export GOOGLE_WORKSPACE_SUBJECT=<your-super-admin@your-domain>
export GOOGLE_CLOUD_PROJECT=cloud-custodian
uv run pytest tools/c7n_gcp/tests/test_workspace.py -k <test> -s -p no:env
```

`-p no:env` matters. `pyproject.toml` has a `[tool.pytest_env]` section that
loads `test.env` from *inside* pytest, which would otherwise override the
exports above and put the committed fake credentials back. That section also
deliberately unsets `GOOGLE_WORKSPACE_SUBJECT` and
`GOOGLE_WORKSPACE_CUSTOMER`, so that replaying recorded data doesn't depend
on whatever a developer happens to have in their environment.

Then scrub the recording before committing it. The recorder sanitizes GCP
project names only, so real user ids, email addresses, names, the domain,
the customer id, and `recoveryEmail` / `recoveryPhone` all come through and
have to be replaced by hand. Watch for stray recordings of unrelated calls
as well; delete any that the test doesn't need.

Finally, change the test back to `replay_flight_data` and confirm it passes
with no other edits.

## If you get 403s on everything

During initial setup we got 403 ("Not Authorized to access this
resource/api") on every Directory API call, including reading the subject's
own record, with all of the above configured correctly. It cleared after a
while with no configuration change on our part -- though clicking around the
admin console may have had some Heisenberg effect. IDK.

So if you hit this and the setup above checks out, wait a bit and retry
before you start rearranging things.
