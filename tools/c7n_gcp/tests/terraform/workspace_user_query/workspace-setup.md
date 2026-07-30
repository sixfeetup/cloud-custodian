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

7. Set up test users.

   This is the state the tests expect. `test_workspace_user_state` asserts
   it, so if that test fails, this table is what to restore the workspace to.

   | user              | admin | delegated admin | 2sv enrolled | 2sv enforced | suspended | org unit               |
   |-------------------|-------|-----------------|--------------|--------------|-----------|------------------------|
   | *the super admin* | yes   | no              | yes          | yes          | no        | `/`                    |
   | `test_admin`      | no    | yes             | yes          | yes          | yes       | `/`                    |
   | `test_needno2sv`  | no    | no              | yes          | no           | yes       | `/test-no-enforcement` |
   | `test_no2sv`      | no    | no              | no           | no           | no        | `/test-no-enforcement` |
   | `test_no2sv_susp` | no    | no              | no           | no           | yes       | `/test-no-enforcement` |

   The documented policy in
   `docs/source/gcp/examples/workspace-user-mfa.rst` filters on
   `isEnrolledIn2Sv: false` *and* `suspended: false`, so:

   - `test_no2sv` is the only user it selects: the CIS-B-GCPF-4.0.0-1.2
     finding.
   - `test_no2sv_susp` differs from it in only the suspended field, so the
     `suspended: false` clause is load bearing. Without that row, a one
     clause policy would select the same users and the test would prove
     nothing about the second clause.
   - `test_admin` is a delegated admin rather than a super admin. The two
     are different, and `isAdmin` alone does not find delegated admins.
   - `test_needno2sv` is enrolled but not *enforced*, so `isEnrolledIn2Sv`
     and `isEnforcedIn2Sv` are seen to vary independently.

   Drop any one of the four and exactly one of those properties disappears,
   so all of them are needed.

   Both `test_no2sv*` users live in `/test-no-enforcement` deliberately.
   With 2sv enforced, an unenrolled user cannot sign in at all -- and
   signing in is the only way to clear google's automatic suspension.
   Putting them outside enforcement is what makes `test_no2sv` recoverable.

   Enrolling 2sv needs a phone or authenticator app per account, and can
   only be done by signing in as that user. There is no API for it, which
   is why this step is manual.

8. Create a sub-organization, `test-no-enforcement`, with 2sv not enforced,
   and move `test_needno2sv`, `test_no2sv` and `test_no2sv_susp` into it.

   This comes before enforcement, because the `test_no2sv*` users are never
   going to enroll, and enforcement would lock them out of the sign in that
   step 10 needs.

9. Turn on 2sv enforcement on the root organization unit.

   **IMPORTANT! Set up 2sv on the super admin acount first!** Enforcement
   locks out anyone not enrolled, and the super admin is the account the
   tests impersonate.

10. Un-suspend `test_no2sv`, and only that user.

    Google auto suspends freshly created accounts, with
    `suspensionReason: WEB_LOGIN_REQUIRED`, if you create several in quick
    succession. Spacing account creation out avoids it. Once it happens,
    **an admin cannot clear it** -- the REACTIVATE button is greyed out. The
    user has to sign in at https://accounts.google.com and enter a code sent
    to a mobile phone.

    Only `test_no2sv` needs this, and it's only possible because step 8 put
    that user outside 2sv enforcement. If it stays suspended, the documented
    policy selects nothing and the test proves nothing.

    The other users' suspended state doesn't matter to any test, so the
    table just records what google will have left you with. Only
    `test_no2sv` must be unsuspended, and only `test_no2sv_susp` must stay
    suspended.

11. Assign some admin role to test_admin. It doesn't matter which
    one. Whatever is first in the list is fine. :) That makes it a
    delegated admin, which is all the tests care about.

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

Then scrub the recording before committing it, with:

```bash
python tools/c7n_gcp/tests/terraform/workspace_user_query/scrub.py
```

The recorder sanitizes GCP project names only, so everything else about real
users comes through. Don't scrub by hand: we did that once and shipped a real
phone number, because we checked for the fields we thought of rather than the
fields that were there. The script replaces the domain, the super admin's
identity, ids, etags and the customer id, and drops anything that could carry
personal data. It fails if it sees a field it doesn't recognize, so a future
API addition can't slip PII through unnoticed.

The `test_*` local parts are kept as they are: they're already test names, and
`test_workspace_user_state` keys off them.

Watch for stray recordings of unrelated calls as well; delete any that the
test doesn't need.

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
