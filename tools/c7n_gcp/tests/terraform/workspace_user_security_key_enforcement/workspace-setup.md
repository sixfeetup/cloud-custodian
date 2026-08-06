# Setting up to record security key enforcement

This builds on the workspace used for `workspace-user-query`. Do that setup
first, and don't repeat it here:

    tools/c7n_gcp/tests/terraform/workspace_user_query/workspace-setup.md

That covers obtaining a domain, creating the Cloud Identity account, creating
the service account and its key, authorizing domain-wide delegation, enabling
the Admin SDK API, and the test users. Everything below is *additional*.

For what the resulting data means and why these cases exist, see the design
notes in this branch's spec directory.

## 1. More delegated scopes

Edit the existing domain-wide delegation entry, same service account client
id: Security > Access and data control > API controls > Manage Domain-Wide
Delegation. Add:

    https://www.googleapis.com/auth/cloud-identity.policies.readonly
    https://www.googleapis.com/auth/admin.directory.orgunit.readonly
    https://www.googleapis.com/auth/admin.directory.group.member.readonly

leaving `admin.directory.user.readonly` from the first increment in place, for
four scopes in total.

## 2. Enable the Cloud Identity API

In the *service account's* GCP project, not the workspace's organization:

```bash
gcloud services enable cloudidentity.googleapis.com --project <sa-project>
```

## 3. Organizational units

Security key enforcement is a per-org-unit policy, not a user attribute, so
the cases have to be modelled as org units. Create these as children of the
root, and set each one's 2-Step Verification methods under
Security > Authentication > 2-Step Verification, selecting the org unit in
the left panel:

   | org unit path          | 2sv enforced | methods setting              |
   |------------------------|--------------|------------------------------|
   | `/`                    | yes          | any                          |
   | `/admin`               | yes          | security key, codes ip bound |
   | `/admin-global-codes`  | yes          | security key, codes allowed  |
   | `/admin-no-codes`      | yes          | security key only            |
   | `/test-no-enforcement` | no           | any                          |

Read back through the API, those produce:

   | org unit path         | `allowedSignInFactorSet`              | `enforcedFrom` |
   |-----------------------|---------------------------------------|----------------|
   | `/`                   | `ALL`                                 | a timestamp    |
   | `/admin`              | `PASSKEY_PLUS_IP_BOUND_SECURITY_CODE` | a timestamp    |
   | `/admin-global-codes` | `PASSKEY_PLUS_SECURITY_CODE`          | a timestamp    |
   | `/admin-no-codes`     | `PASSKEY_ONLY`                        | a timestamp    |
   | `/test-no-enforcement`| `ALL`                                 | epoch zero     |

Three different values all mean "a security key is required", differing only
in whether a backup security code is allowed and whether it is ip bound. That
is why more than one enforcing org unit is worth having: a fixture with only
one would let an implementation hardcode a single value and still pass.

`enforcedFrom` is a timestamp rather than a boolean, and not-enforced shows up
as `1970-01-01T00:00:00Z`. So `/test-no-enforcement` covers the case of a
permissive factor set with 2sv off entirely.

## 4. A user in an org unit with no policy of its own

Absent means inherit, not unset. To exercise inheritance, at least one test
user must sit in an org unit that has **no** 2sv policy of its own, so that
resolving its enforcement requires walking up to a parent. A child of
`/admin` with nothing configured on it will do.

Without this the inheritance path is never executed, however many org units
exist. Do not skip it: it is the only case that distinguishes a correct
implementation from one that just does a dictionary lookup on the user's own
`orgUnitPath`.

## 5. A group with its own enforcement policy

Security key enforcement can also be scoped to a group rather than an org
unit, and doing this deliberately is what surfaced the precedence question
recorded in the spec, so it is not optional setup.

- Create a group, e.g. `test_admins@<domain>`, and add `test_admin` to it.
- Security > Authentication > 2-Step Verification: select the group (not an
  org unit) in the scope picker, and set methods to security key only or
  passkey. Leave the group's own org unit scope as `/` (root) if prompted;
  the console may combine both into one query.
- Confirm membership via the API rather than assuming the console saved it:

  ```
  GET https://admin.googleapis.com/admin/directory/v1/groups/<group email>/members
  ```

  needs only `admin.directory.group.member.readonly`, already added in step 1.
  `admin.directory.group.readonly` is a different scope, needed only to
  *list or search* groups by name; it is not required once the group's email
  or id is already known, and does not need to be added.

The point of this case: `test_admin` is now covered by two policies for the
same setting, one from its org unit and one from this group, with different
values. Confirm that by re-reading `policies.list` and checking that both
appear with a `policyQuery.group` and a `policyQuery.orgUnit` respectively.
Resolving the conflict between them (via `PolicyQuery.sortOrder`) is exactly
the open question the spec calls out; do not silently pick one when
implementing against this fixture.

## 6. GCP organization IAM binding

Unlike the first increment, this needs the **GCP organization** that Cloud
Identity provisioned for the domain, because the population of admins comes
from an organization IAM policy, and the test users only exist as principals
there.

- Confirm the organization exists, signed in as the workspace super admin:
  `gcloud organizations list`. Cloud Identity provisions it, but it may not
  materialize until someone visits the GCP console.
- Grant an admin role to a test user at the organization node, so the
  bindings have something to find.
- Reading that policy is ordinary GCP auth rather than domain-wide
  delegation, so it needs credentials that can read the organization: either
  the super admin's own ADC, or a service account inside a project in *that*
  organization. A service account in an unrelated project will not do.

This is the part most likely to differ from the first increment, whose
service account lived in an unrelated project and got away with it because
delegation doesn't care where the service account lives.

## Recording

As in the first increment: switch the test from `replay_flight_data` to
`record_flight_data`, run with the credentials exported and `-p no:env`, then
scrub, then switch back. See the Recording section of the
`workspace_user_query` setup document for the mechanics and the reason
`-p no:env` is needed.

Scrub before committing. Beyond the user fields the first increment's scrubber
handles, this recording also carries:

- **Org unit ids**, opaque strings like `id:03ph8a2z27h9xnl`, appearing in
  `orgunits.list` output and, in a different spelling, as
  `orgUnits/03ph8a2z27h9xnl` in `policyQuery.orgUnit`. Both spellings of the
  same id have to be replaced consistently or the join silently breaks.
- **Group ids and names**, in `policyQuery.group` (`groups/<id>`), inside the
  `query` CEL string (`groupId('<id>')`), and the group's own email if it is
  ever fetched directly.
- **The customer id**, in every policy's `customer` field.
- **Policy resource names**, `policies/<id>`.
- Timestamps in `enforcedFrom`, which are harmless but worth normalizing so
  the fixture doesn't churn.

Note the root org unit has no record in `orgunits.list`, so the mapping from
`policyQuery.orgUnit` to a path has to default to `/` for it.
