# Google Workspace security key enforcement

Issue: cloud-custodian/cloud-custodian#10517, the second checkbox
("Security key enforcement"). Stacked on the branch for the first checkbox
("MFA enforcement"), which added `gcp.workspace-user`.

**Status: requirement only.** This states what we think is being asked, so we
can agree on the interpretation before designing anything. No design or
approach here yet, because the key technical question is unverified -- see
Unknowns.

## Motivation

The driving policy issue is `stacklet/platform-initial-policies#1948`,
**CIS-B-GCPF-4.0.0-1.3**, "Ensure that Security Key Enforcement is Enabled for
All Admin Accounts" (Level 2, and CIS marks its assessment status *Manual*).

Its rationale, condensed: Organization Administrators hold the highest
privilege in the organization, so they should be protected by the *strongest*
second factor. Security keys send an encrypted signature rather than a code,
so unlike SMS or one-time passwords they cannot be phished.

Its audit procedure, verbatim in intent:

1. Identify users with Organization Administrator privileges:
   `gcloud organizations get-iam-policy ORGANIZATION_ID`, looking for members
   granted `roles/resourcemanager.organizationAdmin`.
2. Manually verify that Security Key Enforcement has been enabled for each
   such account.

## The requirement, as we read it

A Custodian policy should be able to report **accounts that hold high GCP
privilege but are not required to use a security key**.

That decomposes into three parts, and each is a place our interpretation could
be wrong:

1. **Which accounts are in scope.** CIS says Organization Administrators, and
   its audit procedure defines that as GCP IAM: members with
   `roles/resourcemanager.organizationAdmin` on the organization.
2. **What "security key enforcement" means.** That the account is required to
   use one.
3. **What a finding is.** An in-scope account for which security key
   enforcement is not in effect.

The framing is GCP first: this is a population of **GCP IAM principals**,
enriched with an attribute sourced from Cloud Identity. Cloud Identity is an
implementation detail of where the attribute comes from, not what defines the
population. There is no GCP user resource to enumerate -- GCP has no API that
lists principals, only APIs that report which principal strings appear in a
policy -- so the population comes from reading bindings.

### Principals are not all alike, and that shapes the output

An IAM binding member can be any of the following, verified against the
`Binding.members` description in the `cloudresourcemanager` v1 discovery
document:

`allUsers`, `allAuthenticatedUsers`, `user:{email}`,
`serviceAccount:{email}`, `group:{email}`, `domain:{domain}`,
`principal://...workforcePools/...`, `principalSet://...workforcePools/...`,
and `deleted:` variants.

Only some of those are accounts that could hold a security key, and only some
of *those* are ones we can inspect:

- **`group:` and `domain:` expand.** A group's members are readable with the
  Directory API `members.list`, and nesting needs
  `includeDerivedMembership=true` because a member can itself be a group. The
  returned `Member` has a `type` (`USER`, `GROUP`, `CUSTOMER`, `EXTERNAL`) and
  a `status`. Note `members.hasMember` looks like a cheaper reverse check but
  refuses nested lookups across domains, so expansion is the safer route.
  Expansion needs the scope `admin.directory.group.member.readonly`, which is
  a **second** workspace scope beyond the one the user resource declares.
  A `domain:` that isn't ours may not be enumerable at all.
- **`user:` may or may not be ours.** A `user:` principal is only a
  *reference*. It might be a managed user in the audited Cloud Identity
  customer, or a consumer gmail account, or a user from an entirely different
  workspace tenant. Only the first is inspectable.
- **`serviceAccount:` can't hold a security key at all.** It is legitimately
  exempt rather than unaudited.
- **`principal(Set)://...workforcePools/...` are federated identities.** They
  don't exist in Cloud Identity, and their MFA lives in the upstream identity
  provider, so we can't speak to them.
- **`allUsers` / `allAuthenticatedUsers`** can't hold a key either, but their
  presence on an organization admin binding would be a catastrophe worth
  shouting about.

### One enumerated field, not a boolean

A per principal result has to distinguish *enforced or not* from *could we
even tell*, because those failures mean opposite things. `serviceAccount:`
being exempt is boring and expected: a service account cannot hold a security
key, so there is nothing to fix. An external `user:` or a federated principal
holding organization admin is a genuine hole in audit coverage, and exactly
what an operator needs told. If both collapse into one "unmanaged" value,
either service accounts cry wolf or real blind spots get buried.

We first tried two orthogonal fields, an `enforcement` boolean plus a
`resolution` reason. That was wrong: `enforcement` has no sensible value for a
service account or an external user. Not `no`, which implies a fixable gap,
and not `yes`, which implies compliance. It would have to be null, which makes
it a partial function defined only when resolution says managed. The two
fields are not independent -- one decides whether the other exists -- so this
is a sum type, and modelling it as a product type invents cross products that
mean nothing.

So: **one field with an enumerated value**, which also matches how c7n
annotates computed judgements elsewhere (`c7n:NetworkLocation`,
`c7n:config-compliance`, `c7n:AccessAnalysis` are all single annotations
holding a computed record).

Name not settled, values roughly:

| value             | meaning                                            |
|-------------------|----------------------------------------------------|
| `enforced`        | resolvable, and security key enforcement applies   |
| `not-enforced`    | resolvable, and it does not -- **the finding**     |
| `external`        | a `user:` outside the audited customer; can't tell |
| `federated`       | workforce or workload identity; MFA lives upstream |
| `service-account` | cannot hold a security key; legitimately exempt    |
| `all-users`       | `allUsers` / `allAuthenticatedUsers`; alarming     |

The CIS-B-GCPF-4.0.0-1.3 finding is `not-enforced`. The coverage holes are
`external` and `federated`, selectable deliberately:

```yaml
filters:
  - type: value
    key: <the field>
    op: in
    value: [external, federated]
```

Hopefully a real organization has no external or federated principal holding
organization admin. If it does, that is precisely what the operator needs to
know, which is why those are their own values rather than folded into a
generic "unknown".

**Caveat to keep in mind.** One field does conflate two questions -- "is it
compliant?" and "why can't we tell?" -- in a single value space. A naive
`op: ne, value: enforced` would flag service accounts too. Mitigated by making
the finding an explicit value rather than a negation, but it is a foot gun
worth documenting for users.

## Open question: what counts as an "Organization Administrator"?

**Parked deliberately.** The facts are settled; the decision is not. Come back
to this when designing the filter's schema.

### What CIS says

The #1948 audit procedure is literal and narrow: read the organization's IAM
policy and "look for members granted the role
`roles/resourcemanager.organizationAdmin`". One role, one resource (the org
node), nothing about folders or projects.

### What we verified

Enumerated all 2378 predefined roles via `iam.googleapis.com` `roles.list`
with `view=FULL`:

- **Exactly one role is titled "Organization Administrator"**:
  `roles/resourcemanager.organizationAdmin`, 36 permissions. So CIS's name is
  unambiguous, and there is no sibling role to confuse it with.
- Matching on the *title* rather than the name would be a bug:
  `roles/apigee.admin` is titled "Apigee Organization Admin" and is unrelated.
- **Four predefined roles include
  `resourcemanager.organizations.setIamPolicy`**, i.e. can rewrite the org IAM
  policy and therefore grant themselves anything:
  - `roles/resourcemanager.organizationAdmin` (the CIS one)
  - `roles/iam.securityAdmin`
  - `roles/privilegedaccessmanager.organizationServiceAgent`
  - `roles/privilegedaccessmanager.serviceAgent`

So `roles/iam.securityAdmin` is a real escalation path to exactly the power
CIS 1.3 exists to protect, and CIS doesn't mention it. Neither does it mention
`roles/owner` granted at the org node, nor **custom roles** including that
permission -- and custom roles can't be enumerated from the predefined
catalogue at all, only from the org's own role list.

### Mostly resolved by making the role the subject

"Who is an organization administrator" is not a fixed question: it depends on
which roles you treat as admin-equivalent, which is a policy judgement rather
than a fact. Earlier drafts treated that as something *we* had to decide, and
listed options (hardcode the CIS role, hardcode a broader list, add a config
knob).

That mostly evaporates once the role is the subject. The policy author selects
roles with an ordinary filter expression on the role name, so:

- CIS #1948 is satisfied by matching the one literal name.
- A real organization can write a broader expression, without us inventing
  benchmark policy or adding schema.

What remains is not a decision but a capability, deferred to the later
increment described below: selecting roles by *permission equivalence* rather
than by name, e.g. "any role granting
`resourcemanager.organizations.setIamPolicy`". That is the only way to catch
organization custom roles, since name matching can't anticipate them.

## What we already know

Established while implementing the first checkbox, and worth not re-deriving:

- **The Directory API `User` object has no security key field.** Verified
  against both the live discovery document and the copy bundled with
  `google-api-python-client`. It exposes exactly two 2SV booleans,
  `isEnrolledIn2Sv` and `isEnforcedIn2Sv`, and neither indicates the *type*
  of factor. The only other key-ish field is `sshPublicKeys`, which is
  unrelated (OS Login).
- **So `gcp.workspace-user` alone cannot satisfy this control.** That is why
  it was scoped out of the first increment rather than bolted on.
- **In the Workspace admin console, the relevant setting is per org unit**
  (or group): Security > Authentication > 2-Step Verification has a *methods*
  choice that includes "Only security key". That is a policy applying to a
  set of users, not an attribute of a user.
- **`isAdmin` is not the same thing as `organizationAdmin`.** `isAdmin` means
  Workspace *super* administrator; `isDelegatedAdmin` means a narrower
  Workspace admin role; `roles/resourcemanager.organizationAdmin` is a *GCP
  IAM* binding. These sets overlap in practice but are not equal, and CIS 1.3
  names the IAM one. Using `isAdmin` as a proxy would produce a policy that is
  wrong in both directions.

## Unknowns, to be resolved before designing

1. **~~Where security key enforcement state lives~~** RESOLVED. It is readable.
   See "Reading enforcement: verified against a live tenant" below.
2. **~~Whether the enforcement signal can be attributed to a principal.~~**
   RESOLVED. Org unit inheritance and group membership (including nested
   group membership) are both readable and both verified against a live
   tenant, and conflict resolution between simultaneously-matching policies
   is understood. See unknown 6, below.
3. **How to identify the in-scope accounts.** Reading the organization IAM
   policy is a *global*, organization level read rather than the project
   scoped calls the GCP provider mostly makes. c7n already has the pieces:
   a `gcp.organization` resource (`cloudresourcemanager` v1, `scope = global`)
   and an `iam-policy` filter supporting `user-role` semantics that annotates
   `c7n:matched-iam-bindings` with matched `{role, member}` pairs. So the
   population is expressible today; what needs checking is the shape, since a
   policy over `gcp.organization` yields *one organization resource*, not the
   admins inside it.
4. **~~What is a finding about?~~** Resolved: the subject is the role, with
   the users holding it as a computed property. See "The subject is the role"
   below. A new problem replaces it, recorded there: `gcp.iam-role` enumerates
   the predefined catalogue rather than the roles actually in use in an
   organization, and excludes custom roles.
5. **Credentials, and whether one policy run can hold both.** Org IAM read is
   ordinary GCP auth. Everything else is a workspace call needing domain-wide
   delegation, and **four** scopes are now known to be required rather than
   two: `admin.directory.user.readonly`,
   `admin.directory.orgunit.readonly`, `cloud-identity.policies.readonly`,
   and `admin.directory.group.member.readonly` for group expansion. Plus two
   APIs enabled in the service account's project, `admin.googleapis.com` and
   `cloudidentity.googleapis.com`.

   The scopes plumbing added in the first increment threads scopes through the
   *enumerate* path only, not filters, so a filter needing its own scopes --
   several of them, against two different services -- is new ground and is
   probably the largest piece of implementation work here.
6. **~~How `sortOrder` resolves conflicting policies~~** RESOLVED, empirically,
   including the multi-level and nested-group cases.

   A user can be covered by an org-unit-scoped policy and a group-scoped
   policy simultaneously, for the same setting, with different values --
   confirmed in this tenant: `/` gives `ALL`, the group `test_admins` gives
   `PASSKEY_PLUS_IP_BOUND_SECURITY_CODE`, both apply to `test_admin`.

   `PolicyQuery.sortOrder` is an API field (`cloudidentity` v1, `readOnly`,
   type `double`), documented only as "the decimal sort order of this
   PolicyQuery... relative to all other policies with the same setting
   type... there are no duplicates within this set." The API says nothing
   about which direction wins, and no published Google documentation
   describes the precedence algorithm (checked the Cloud Identity policy
   concepts page, 404; a Workspace admin help page, no relevant content).

   **Confirmed: higher `sortOrder` wins**, and its structure is fully
   decodable. Built a synthetic 3-level org unit chain (`O1 ⊃ O2 ⊃ O3`,
   each a child of the last) and three nested groups (`G1 ⊆ G2 ⊆ G3`, i.e.
   `G1` is a member of `G2`, `G2` a member of `G3`), then set a plain
   org-unit policy at each of `O1`/`O2`/`O3` plus one group-paired policy at
   each (`O1+G1`, `O2+G2`, `O3+G3` -- respecting the console's "one group per
   org unit" limit, see below). Resulting `sortOrder`s for
   `enforcement_factor`, ascending:

   | scope | sortOrder |
   |---|---|
   | root | 201.00034 |
   | (sibling org units, increment-1 fixture) | 202 |
   | O1 | 202 |
   | O1+G1 | 202.00001 |
   | O2 | 203 |
   | O2+G2 | 203.00001 |
   | O3 | 204 |
   | O3+G3 | 204.00001 |

   Two clean rules fall out of this:

   - **The integer part of `sortOrder` encodes org unit depth from root,
     exactly.** Every direct child of root -- five of them across old and
     new fixtures -- landed on `202`. `O2` (root's grandchild) landed on
     `203`. `O3` (great-grandchild) landed on `204`. One full integer per
     level, not creation order (`O1`/`O2`/`O3` were created in one batch,
     latest in the tenant, and still track depth).
   - **A group-paired policy always gets `sortOrder = <its org unit's
     sortOrder> + 0.00001`.** This is the literal mechanism behind "group
     settings override organizational units" (Google's own docs,
     `support.google.com/a/answer/9176657`): a fixed, tiny epsilon bump,
     reserved for exactly the one group override an org unit is allowed to
     have. Depth dominates the epsilon -- a deeper org unit's *plain* policy
     (e.g. `O3` at `204`) always outranks a shallower org unit's
     *group-overridden* policy (e.g. `O1+G1` at `202.00001`), so the group
     bonus only lets a policy jump its own org-unit level, never leapfrog a
     more specific descendant org unit.

   This also settles, structurally, that `entity.org_units` for CEL matching
   must include the full ancestor chain (self plus every parent up to root),
   not just the user's own leaf org unit -- there would be no reason for
   Google to carefully rank every ancestor level against every other if only
   the nearest one could ever match a given user.

   **Nested/derived group membership counts for policy matching --
   confirmed cleanly, and this reverses an earlier wrong reading along the
   way.** Created a test user, member only of `O3` and only a *direct*
   member of `G1` (nested two levels below `G3`). `hasMember` (Directory
   API) reported the user as a member of `G1`, `G2`, and `G3` alike, but
   that only shows the Directory API resolves nesting for its own purposes,
   not that the policy engine does.

   First read of the user's Admin console security page showed "security key
   only" -- matching `O3`-alone's *then* value (`PASSKEY_ONLY`), not
   `O3+G3`'s (`PASSKEY_PLUS_SECURITY_CODE`), which briefly looked like
   confirmation that only *direct* membership counts (`test_admin`, not
   `G3`). That reading turned out to be wrong. After changing `O3`-alone's
   values (`enforcement_factor` to `ALL`, `enforcement.enforcedFrom` to
   epoch/off) and re-checking, the console showed *unchanged* text tracking
   `O3+G3`'s value instead, and eventually, once `O3+G3`'s own factor was
   separately changed to `ALL`, the qualifier text disappeared entirely,
   exactly matching `O3+G3`'s enforcement (`ON`) and factor (`ALL`, hence no
   qualifier) at every step -- never `O3`-alone's. There was no caching
   delay; the console was accurately reflecting the live policy the whole
   time, and the correct reading was `O3+G3`, not `O3`-alone, from the
   start. This is also the cleanest possible test of the question, because
   `O3+G3`'s org-unit half is the user's own leaf org unit, not an ancestor
   -- so the result cannot be explained by the still-separately-confirmed
   ancestor-chain behavior above. The only way `O3+G3` can govern this user
   is if its group half (`G3`) matches through two levels of nesting from a
   direct membership in `G1`.

   **Conclusion: group-scoped policy matching resolves nested group
   membership**, the same as `members.list?includeDerivedMembership=true`
   and `hasMember` -- a c7n filter must do the same (derived-inclusive
   membership resolution), not check direct membership only.

   **`CreatePolicy()` is blocked for this setting type entirely, confirmed
   by isolating the variable rather than assumed.** An early attempt to
   create a second group-scoped policy via the API (`entity.groups.exists`
   alone, no org-unit clause) failed with `CreatePolicy() is not supported
   for this setting type`, using both a malformed and later the correct
   group id -- ruling out a bad id as the cause. It was tempting to read
   this as "the setting type can never be created via the API", but that
   generalized from only one query shape (bare group, no org unit) and only
   against an org unit (`test_admins`' root) that already had a conflicting
   policy. Isolated properly: created a brand-new org unit with **no**
   existing policy, and tried a plain **org-unit-only** create against it.
   Same error. That rules out both the bare-group shape and a pre-existing
   conflict as the cause -- this setting type cannot be created via the API
   in any shape tried. The console is the only way to write it. This also
   means no future write-side ("remediate") action is possible for this
   setting, consistent with CIS framing this control as a manual check.

   **The "one group per org unit" limit is documented in the console UI
   itself**, not inferred: the group-picker in Security Settings reads
   "Customize settings for a group within an organizational unit. One group
   per organizational unit." Confirmed this is a real console/data limit,
   not just a display quirk, since the sortOrder table above shows exactly
   one group-paired policy per org unit, never two competing ones for the
   same org unit.

   **"Security group" is a label, not a separate resource type or a
   requirement.** The console nudges toward converting a group into a
   "security group" when applying a policy to it, but this is just the
   `cloudidentity.googleapis.com/groups.security` label on an ordinary
   `Group` (per the `Group.labels` field description in the `cloudidentity`
   v1 schema) -- informational/hygiene, not required for `entity.groups`
   matching to work. Plain groups (`test_admins`, `test_other_admins`, and
   the synthetic `G1`/`G2`/`G3`) all matched correctly without it. Worth
   noting the label is irreversible once added, per the same field
   description ("cannot be removed once added") -- not touched in this
   tenant.

   One remaining gap: the *combined* effect of ancestor-chain org-unit
   matching together with nested-group matching, at full multi-level scale
   (i.e., watching a real user resolve across all of root/O1/O2/O3 and
   G1/G2/G3 simultaneously, not just the two-policy pairs tested so far) has
   not been separately observed -- though there is no remaining mechanism
   left unconfirmed that would make it behave differently from what the
   sortOrder table above predicts.

   **Inheritance from an org unit with no explicit policy of its own --
   CLOSED, and `sortOrder` is dynamically recomputed, not a fixed label.**
   Removed `O3`'s own plain `enforcement_factor`/`enforcement` policies
   (console: set back to "inherit"). `O3+G3` (the only remaining policy
   naming `O3`) still governed the test user afterwards, matching the rule
   above. The interesting part is *how*: re-fetching that exact policy
   object (same `name`,
   `policies/awwlb5moecokbuxwaojnvrfpueffc`) showed its `sortOrder` had
   changed from `204.00001` to exactly `204` -- the slot `O3`-alone
   vacated. So `sortOrder` is not a fixed identifier assigned once; Google
   recomputes it as sibling policies for the same org unit are added or
   removed. This closes the inheritance gap and explains it mechanically,
   rather than just by outcome: with no plain policy at `O3`, the
   group-paired policy is the only remaining candidate for that org unit
   and is renumbered to occupy its slot.

   A tempting simplification is a hierarchy-climbing restatement: find the
   nearest org unit (own, or ancestor) with a policy, then apply its
   group-paired policy if the user matches (direct or nested) else its
   plain policy. This holds in every case tried, but it is a mnemonic, not
   the mechanism, and it can be misread: with `O3`'s plain policy removed
   and only `O3+G3` remaining, it is natural to think "`O3` has no real
   policy, so `O2` is the nearest org unit that does" -- but `O3` *does*
   have a policy (`O3+G3`, conditional though it is), so the climb never
   reaches `O2` at all. Confirmed with this exact case: `O3+G3`
   (`sortOrder 204`) governed over both `O2` (`203`) and `O2+G2`
   (`203.00001`), because it matched and outranked them, full stop -- not
   because of any reasoning about which org unit is "nearest."

   **Decided: implement flat evaluation, not the climbing shortcut.** The
   climbing restatement is only valid given the current, empirically
   observed shape of `sortOrder` allocation (depth-encoded integers, one
   group epsilon per org unit) -- a shape that is not documented or
   guaranteed anywhere by Google, and could change. `sortOrder`'s only
   documented contract is that it is a total order ("no duplicates within
   this set") for the policies of a given setting type. A hand-built
   climbing algorithm risks silently producing wrong answers if Google ever
   changes how it allocates values; evaluating every candidate and taking
   the maximum only depends on the one thing that actually is part of the
   contract. So the filter's resolution algorithm is: fetch every policy
   for the setting type, evaluate each one's org-unit and group clauses
   against the target user (org-unit ancestry; group membership, direct or
   nested) independently, keep the matching set, and take the policy with
   the highest `sortOrder`. No hierarchy traversal, no assumption about
   integer-per-depth or epsilon-per-group.

   **Concrete shape of the flat algorithm**, keyed on structured fields
   rather than parsing `policyQuery.query` (CEL text -- fine for exploring
   by hand, not something to build production matching on). Verified via
   the live tenant that `PolicyQuery.orgUnit` and `PolicyQuery.group` are
   already parsed, first-class fields -- `group` is genuinely *absent* (not
   an empty string) on plain policies, present only on group-paired ones,
   so `(orgUnit, group-or-absent)` is a well-defined lookup key straight off
   the API response, no string matching needed:

   ```
   mapping = {(p.policyQuery.orgUnit, p.policyQuery.get("group")):
              (p.policyQuery.sortOrder, p.setting.value)
              for p in policies.list(filter=setting.type == ...)}

   for user in managed_users:
       ous    = ancestor_chain(user.orgUnitPath)      # self .. root
       groups = transitive_groups(user) | {None}      # nested-inclusive + sentinel
       candidates = [mapping[(ou, g)] for ou in ous for g in groups
                     if (ou, g) in mapping]
       winner = max(candidates, key=lambda c: c[0])    # highest sortOrder
   ```

   `transitive_groups` must be nested-inclusive. Two Directory-API-style
   candidates were checked and found to return only *direct* membership --
   `groups.list?userKey=` (verified: returned only `G1`, not `G2`/`G3`, for
   the nested test user) and, by nature, `hasMember`/`members.list` unless
   `includeDerivedMembership=true` is set. The one that actually is
   nested-inclusive is `cloudidentity` v1's
   `groups.memberships.searchTransitiveGroups` -- verified against the
   live tenant, not just cited: called for the same nested test user
   (direct in `G1` only) and it returned all three, correctly labeled
   `relationType`: `G1` `DIRECT`, `G2`/`G3` `INDIRECT`. Needs the
   `cloud-identity.groups.readonly` scope (a fifth Workspace scope beyond
   the four already known, and its DWD authorization took roughly 30
   seconds to propagate before it would mint -- unlike the
   `cloud-identity.policies` scope changes earlier in this investigation,
   which took effect immediately).

   Two real quirks in using it, found empirically rather than from the
   reference: the `query` parameter's CEL expression *requires* a labels
   clause (e.g. `'cloudidentity.googleapis.com/groups.discussion_forum' in
   labels`) alongside `member_key_id == '...'` -- omitting it returns `400
   INVALID_ARGUMENT`, even though the field description reads as though
   the labels clause is for narrowing rather than mandatory. And the
   method's own description states it is **only available on Google
   Workspace Enterprise Standard, Enterprise Plus, Enterprise for
   Education, or Cloud Identity Premium** editions, 403 otherwise -- this
   tenant qualifies (call succeeded), but that is a real deployment
   constraint for a c7n policy, not just a hypothetical one, since it can't
   be assumed to hold for every tenant a policy runs against.

   **Refinement: precompute per org unit, not per user.** The per-user loop
   above computes `max over (ou' in ancestor_chain(user_ou), g in
   groups(user)) of mapping[(ou', g)]` -- a max over a product of two
   independent sets (the ancestor chain depends only on the user's own OU;
   the groups depend only on the user). Independent axes mean the max can
   be split and reordered without changing the answer:

   ```
   max over g in groups(user) of (
       max over ou' in ancestor_chain(user_ou) of mapping.get((ou', g)))
   ```

   The inner term depends only on `(user_ou, g)`, not on which user it is,
   so it can be precomputed once per distinct org unit rather than
   recomputed per user:

   ```
   effective[ou] = {
       g: max(mapping[(ou2, g)] for ou2 in ancestor_chain(ou)
              if (ou2, g) in mapping, key=lambda c: c[0])
       for g in all_groups_and_none_seen_in(mapping)
   }

   for user in managed_users:
       groups = transitive_groups(user) | {None}
       winner = max((effective[user.ou][g] for g in groups
                     if g in effective[user.ou]), key=lambda c: c[0])
   ```

   This is a pure re-association of the same verified computation, not a
   new assumption -- it doesn't depend on anything about how `sortOrder` is
   allocated, only on the max being taken over the same product set as
   before. It pays the ancestor-chain walk once per distinct org unit
   rather than once per user, which matters because org units are
   typically far fewer than users.

7. **Is there an API shortcut instead of resolving policies ourselves?**
   Partially. Checked every method on `cloudidentity` v1 and v1beta1
   `policies.*` -- only `create`/`get`/`list`/`patch`/`delete`, no
   `resolve`/`evaluate` method that returns an already-resolved value for a
   given user. So there is no way to ask the Cloud Identity API directly
   "what does this setting evaluate to for this user" -- resolving
   `enforcement_factor` for a user means fetching `policies.list` and
   reimplementing the matching just verified above (ancestor org units,
   nested groups, highest `sortOrder` wins).

   For the *other* 2SV setting, though, there is a shortcut: the Directory
   API's `User` resource has `isEnforcedIn2Sv` (`admin.directory.user`
   schema, `Output only`, boolean) -- Google's own server-resolved answer to
   whether `two_step_verification_enforcement` applies to this user, readable
   with `admin.directory.user.readonly`, a scope already needed and already
   granted from increment 1. Verified against both test users in this
   tenant: matches what was independently found by hand for each (`True` for
   `api-test-u`, governed by the nested-group `O3+G3` policy; `True` for
   `test_admin`). No equivalent field exists for `allowedSignInFactorSet` --
   nothing on `User`, nothing elsewhere -- so the factor-set resolution this
   whole increment is actually about still has to be computed by the filter
   itself; this only avoids reimplementing resolution for the boolean
   enforcement setting, which is not the setting CIS's control cares about.

## The subject is the role

The goal is that *admin users have security keys enforced*. "Admin users" is
vague, but notionally it means the users holding the role Organization
Administrator. So the subject of the policy is **the role**, and the users
holding it are a **computed, set-valued property** of it.

Bindings are an implementation detail, the way a foreign key is: they are how
GCP happens to store the role-to-user relationship. Earlier drafts of this
spec rejected role-as-subject on the grounds that the `Role` object has no
members field, but that is arguing from storage rather than from the domain.
Complaining that `Role` has no members is like complaining that a customer
record doesn't contain its orders.

That gives:

- **subject**: `gcp.iam-role`, which already exists.
- **policy configuration**: an expression on the role name, in an ordinary
  `value` filter. Nothing new to invent -- `glob`, `regex` and `in` are all
  already available. CIS's answer is one literal name; a real organization can
  write something broader.
- **computed property**: the set of users holding the role, obtained by reading
  the organization's IAM policy. Computing a property with extra API calls is
  routine in c7n (`c7n:matched-iam-bindings`, `c7n:NetworkLocation`,
  `c7n:AccessAnalysis` are all of this kind).
- **verdict per user**, using the enumerated field above, so that unresolvable
  principals stay visible instead of being filtered out of existence.

This also resolves what earlier drafts got stuck on. Starting from Workspace
users inverts the population and can never see an external or federated admin;
starting from the organization gives one pass/fail row for the whole org.
Starting from the role keeps the population authoritative *and* gives
something per-user to report.

### The design: a `member-enforcement` filter on `gcp.iam-role`

A custom filter, not a `RelatedResourceFilter` subclass. See "Why not
RelatedResourceFilter" below.

```yaml
policies:
  - name: gcp-org-admins-without-security-keys
    resource: gcp.iam-role
    filters:
      - type: value
        key: name
        value: roles/resourcemanager.organizationAdmin
      - type: member-enforcement
        enforcement: [enforced]
        complement: true
```

**Selecting roles is not this filter's job.** An upstream `value` filter
narrows the roles; `member-enforcement` only evaluates whatever roles reach
it. That keeps role selection in ordinary c7n vocabulary (`glob`, `regex`,
`in`) instead of inventing a `roles:` option, and it means the
permission-equivalence work below composes without touching this filter.

Because `gcp.iam-role` enumerates the whole predefined catalogue (see the
known problem above), a policy that forgets the upstream filter would ask for
an organization IAM evaluation against ~2378 roles. **Error out above a
threshold** -- 999 as an opening figure -- rather than doing it. The message
should point at adding a role filter.

**Schema.** `enforcement` accepts one verdict or a list of them, and
`complement` selects everything else:

```python
VERDICTS = ('enforced', 'not-enforced', 'external',
            'federated', 'service-account', 'all-users')

schema = type_schema(
    'member-enforcement',
    enforcement={'oneOf': [
        {'enum': list(VERDICTS)},
        {'type': 'array', 'items': {'enum': list(VERDICTS)}},
    ]},
    complement={'type': 'boolean'},
)
```

So `enforcement: [enforced]` with `complement: true` is shorthand for
`[not-enforced, external, federated, service-account, all-users]`. Note this
makes the foot gun documented above easy to write, since the complement
includes `service-account`, which is legitimately exempt. The docs should push
readers toward naming `not-enforced` explicitly when that is what they mean.

`complement` was chosen over `not` because it is set complement rather than
boolean negation, and c7n already uses `not` for block filters
(`c7n/filters/core.py:497`) and `op: ne` / `not-in` inside value filters.
Both `oneOf` string-or-array and enumerated properties are established c7n
idioms (`tools/c7n_gcp/c7n_gcp/filters/iampolicy.py:24-35`,
`c7n/filters/policystatement.py:71-77`).

**Mechanism.** For the roles it receives, the filter:

1. reads the organization IAM policy,
2. finds bindings for those roles and takes their `members`,
3. interprets each member string, expanding `group:` and `domain:`
   recursively (`members.list` with `includeDerivedMembership=true`),
4. builds an org-unit-path to enforcement mapping, as verified below:
   `policies.list` for the two 2sv settings, `orgunits.list` to turn opaque
   org unit ids into paths, then propagates root to leaves so every path has
   an effective value,
5. for each `policies.list` result that is group scoped, resolves the
   group's members (`groups/{key}/members`) separately, since group
   membership is not a field on the user and has no inheritance shortcut,
6. for a managed user, combines the org-unit-derived value and any
   group-derived value using `PolicyQuery.sortOrder` -- direction unverified,
   see the unknowns,
7. assigns each resulting principal a verdict from `VERDICTS`,
8. keeps roles that have at least one member matching the selected verdicts,
9. annotates the matching members onto the role.

Steps 1, 4 and 5 are bulk reads independent of how many roles or members there
are, so they should happen once per policy run rather than per role.

**Annotation key:** `c7n:matched-enforcement-members`.

Conformed to the existing convention, which is `c7n:` followed by a single
segment -- no dots, and no provider or resource namespacing. Dots appear in
this codebase only in logger names (`c7n.policy`, `c7n.output.blob`), never in
annotations.

Style is mixed between kebab-case (`c7n:matched-iam-bindings`,
`c7n:config-compliance`) and CamelCase (`c7n:NetworkLocation`,
`c7n:MatchedSnapshots`), but for "members matched by a filter" the kebab
`matched-` form dominates: `matched-security-groups` and `matched-subnets`
(`c7n/filters/vpc.py:27,79`), `matched-iam-role` (`c7n/filters/iamrole.py:52`),
`matched-kms-key` (`c7n/filters/kms.py:47`), `matched-iam-bindings`
(`tools/c7n_gcp/c7n_gcp/filters/iampolicy.py:14`), `matched-findings`.

Note nothing enforces any of this: annotations are arbitrary dict keys on a
plain dict, and collisions are unguarded.

**Annotation value.** A list of objects with `user`, `member` and
`enforcement`, where `member` is the binding member string the principal came
from, and `user` is present only when the principal resolves to a user:

```json
[{"user": "alice@example.com",
  "member": "group:admins@example.com",
  "enforcement": "not-enforced"},
 {"user": "bob@example.com",
  "member": "user:bob@example.com",
  "enforcement": "enforced"},
 {"member": "serviceAccount:ci@proj.iam.gserviceaccount.com",
  "enforcement": "service-account"}]
```

This does two things at once. Carrying the verdict per principal is what makes
the annotation useful rather than a bare list of names: a role can match
because of several principals for different reasons, and the reason is what an
operator acts on. Keeping `member` alongside `user` preserves provenance --
after `group:` or `domain:` expansion the resolved users do not appear
verbatim in the IAM policy, so without it you couldn't tell which binding to
edit, or that a finding came via a group at all.

`user` being absent is meaningful rather than missing data: it marks the
principals that are not users, which is exactly the `service-account`,
`federated` and `all-users` verdicts.

For `external` the principal *is* a user, just not one we can inspect, so
`user` **is** populated. That gives an operator a lever for further
investigation -- an address to chase in another tenant or with its owner --
which is more useful than recording only that we couldn't tell.

There is precedent for object-valued annotations in this area:
`c7n:matched-iam-bindings` is documented as a list of `{role, member}` dicts
(`tools/c7n_gcp/c7n_gcp/filters/iampolicy.py:83`).

**Output shape.** Rows are roles. The offending members arrive as the
annotation, readable with
`custodian report --field members='"<annotation key>"'`, where the `list:` and
`count:` prefixes also work (`c7n/reports/csvout.py:141-150`). One row per
offending member is not what this produces; see the superseded section below
for why that granularity question is separate.

### Reading enforcement: verified against a live tenant

All of the following was confirmed by calling the real APIs against the
`riversnake.com` Cloud Identity tenant, not read from documentation. The
reference docs are no help here: `Setting.type` is documented only as
"Required. Immutable. The type of the Setting. ." and `value` is an untyped
protobuf `Struct`, so the possible values appear nowhere. The captured request
and response are in `riversnakejim.request` and `riversnakejim.response` beside
this spec.

**The API.** `policies.list` on the Cloud Identity API,
`cloudidentity.googleapis.com/v1/policies`
(https://cloud.google.com/identity/docs/reference/rest/v1/policies/list),
filtered server side with CEL, e.g.
`customer == "customers/my_customer"`. It returned 180 policies over 5 pages
for a tenant with 5 users, so this is a bulk read, not a per-user one.

**The settings that matter.** Two are needed, not one:

| `setting.type`                                               | field                    | meaning                        |
|--------------------------------------------------------------|--------------------------|--------------------------------|
| `settings/security.two_step_verification_enforcement_factor` | `allowedSignInFactorSet` | which factors are permitted    |
| `settings/security.two_step_verification_enforcement`        | `enforcedFrom`           | whether 2sv is required at all |

Related settings also present, not needed here but useful to know exist:
`two_step_verification_enrollment`, `two_step_verification_grace_period`,
`two_step_verification_sign_in_code`, `two_step_verification_device_trust`,
`security.advanced_protection_program`, `security.passkeys_restriction`.

**`allowedSignInFactorSet` is not a boolean, and "enforced" is a set of
values.** Observed in a tenant deliberately configured with one org unit per
case:

| org unit path         | `allowedSignInFactorSet`              | `enforcedFrom`             |
|-----------------------|---------------------------------------|----------------------------|
| `/`                   | `ALL`                                 | `2026-07-30T21:46:02.046Z` |
| `/admin`              | `PASSKEY_PLUS_IP_BOUND_SECURITY_CODE` | `2026-07-30T21:46:02.046Z` |
| `/admin-global-codes` | `PASSKEY_PLUS_SECURITY_CODE`          | `2026-07-30T21:46:02.046Z` |
| `/admin-no-codes`     | `PASSKEY_ONLY`                        | `2026-07-30T21:46:02.046Z` |
| `/test-no-enforcement`| `ALL`                                 | `1970-01-01T00:00:00Z`     |

So **three** distinct values all mean "a security key is required": they differ
only in whether a backup security code is also allowed, and whether that code
is IP bound. `PASSKEY_ONLY` is strictest. Hardcoding a single value would have
been wrong, and no documentation enumerates these -- the names above were
recovered by configuring each case in the admin console and reading back what
the API returned.

Note `enforcedFrom` is a **timestamp, not a boolean**, and
`1970-01-01T00:00:00Z` is how "not enforced" appears. A restrictive factor set
with 2sv unenforced is therefore a real and distinct case: the factor set alone
does not establish enforcement.

**Attribution to a user needs a second API and a join.** The policy response
carries *no* org unit metadata -- no path, no name, no parent, just
`orgUnits/<opaque id>`. Users carry `orgUnitPath`, a path. Joining them needs
`orgunits.list` on the Admin SDK
(`admin/directory/v1/customer/my_customer/orgunits?type=all`), which supplies
`orgUnitId`, `orgUnitPath`, `parentOrgUnitId` and `parentOrgUnitPath`.

Two traps found by doing it:

- **The ids are spelled differently on each side.** `orgunits.list` returns
  `orgUnitId` as `id:03ph8a2z...` while `policyQuery.orgUnit` is
  `orgUnits/03ph8a2z...`. A naive split produces an empty mapping *silently*.
- **The root org unit has no record.** `orgunits.list` returned only the four
  child org units; `/` is absent, so the root policy's org unit id resolves to
  nothing and must be defaulted to `/`.

**Inheritance.** Absent means inherit, not unset: the tenant had 156 policies
on `/` and only 6 on a child org unit. So the mapping has to be computed by
walking from the root down, child overriding parent, after which a user's
`orgUnitPath` is a direct lookup. `blockInheritance` on `OrgUnit` is deprecated
("setting its value has no effect"), so plain parent-child inheritance is the
only rule. Caveat: in the current test tenant every user sits in an org unit
that has its own explicit `enforcement_factor` policy, so **the inheritance
walk is never exercised**. Testing it needs a user in an org unit without its
own policy, e.g. a child of `/admin`.

**Groups: verified, and this is a real second code path, not an edge case.**
After adding a group `test_admins` containing `test_admin`, and setting
`PASSKEY_PLUS_IP_BOUND_SECURITY_CODE` scoped to that group, the tenant now has
a group scoped policy:

```
query: entity.groups.exists(group, group.group_id == groupId('01opuj5n2o9gbsy'))
    && entity.org_units.exists(org_unit, org_unit.org_unit_id == orgUnitId('03ph8a2z1t5tdog'))
policyQuery.group:   groups/01opuj5n2o9gbsy
policyQuery.orgUnit: orgUnits/03ph8a2z1t5tdog
setting.value:       {"allowedSignInFactorSet": "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE"}
```

Three things this settles or corrects:

1. **The earlier claim that a compound query leaves both convenience fields
   empty was wrong, at least for `&&` of two single valued clauses.** Both
   `group` and `orgUnit` are populated here even though the query has both
   clauses. The undocumented case is `||`, or a clause matching more than one
   group/org unit -- still unverified.
2. **Group membership is not a field on the user**, so it cannot be resolved
   the way org unit inheritance is. It needs its own lookup:
   `groups/{groupKey}/members` on the Admin SDK Directory API
   (`admin.directory.group.member.readonly` -- confirmed sufficient by itself;
   `admin.directory.group.readonly`, needed only to *list* groups by name, is
   not required if the group key is already known). A member's `type` is
   `USER` or `GROUP` (nested groups), and `includeDerivedMembership=true`
   resolves nesting.
3. **`test_admin` is now covered by two policies that disagree**, for the same
   setting: the OU-only policy on `/` gives `ALL`; the group+OU policy gives
   `PASSKEY_PLUS_IP_BOUND_SECURITY_CODE`. Something has to pick a winner, and
   the mechanism appears to be `PolicyQuery.sortOrder`
   ("the decimal sort order of this PolicyQuery... relative to all other
   policies with the same setting type"). Observed values for this setting:
   `201.00034` (root OU alone), `202` (each other OU alone), `201.00109` (the
   group+OU policy). These are different from each other, so ordering is real,
   but **the direction (lowest wins? highest wins?) and the general algorithm
   are not verified** -- this is the next thing to check before relying on it.

So group scoped enforcement is not an edge case to defer: this tenant already
exercises it, and correctly attributing a verdict to `test_admin` requires
resolving both the org unit and the group path and combining them via
`sortOrder`.

**Scopes and enablement, in total.** Four delegated scopes:

- `admin.directory.user.readonly` (users)
- `admin.directory.orgunit.readonly` (the org unit join)
- `cloud-identity.policies.readonly` (the policies)
- `admin.directory.group.member.readonly` (group membership, confirmed
  sufficient on its own -- `admin.directory.group.readonly` is a distinct
  scope needed only to list/search groups by name, not to read the members
  of a group whose key is already known)

and two APIs enabled in the service account's project: `admin.googleapis.com`
and `cloudidentity.googleapis.com`. Each missing piece fails differently and
the distinction is worth knowing: a scope missing from the domain-wide
delegation entry fails at the *token endpoint* with
`unauthorized_client`, before any API call; an API not enabled in the project
fails at the *API* with 403 `SERVICE_DISABLED`.

### Why not RelatedResourceFilter

c7n has a join framework, `c7n/filters/related.py`, used widely for
security-group, subnet, vpc, kms-key and iam-role filters. It does not fit
here, for three reasons:

1. **The join key has to be a field on the resource.** `get_related_ids` runs
   a jmespath against the resource dict (`c7n/filters/related.py:37-39`), but
   `Role` has no members field -- the relationship lives in a separate
   document, the organization IAM policy. There is no `RelatedIdsExpression`
   to write.
2. **Ids are opaque strings to it.** `related.get(rid)`
   (`c7n/filters/related.py:80`) is a dict lookup with no notion of
   `user:` / `group:` / `domain:` / `serviceAccount:` / `principalSet:`
   prefixes, and nowhere to put recursive group expansion.
3. **Unresolvable ids cannot carry a verdict.** They either warn and skip or
   count as found when the filter seeks `value: absent`
   (`c7n/filters/related.py:81-94`), which cannot distinguish legitimately
   exempt from invisible to us.

It could still serve a *later* hop: if something has already annotated a role
with member emails, then `RelatedIdsExpression = 'c7n:members[]'` joins to
`gcp.workspace-user` conventionally -- though `get_related` would need
overriding, since its index is keyed on `model.id`
(`c7n/filters/related.py:53`), which is the numeric id for workspace users
while bindings supply emails.

### Later increment: permission-equivalent roles

CIS names one role, but other roles confer the same power -- see the verified
list above, notably `roles/iam.securityAdmin`. Rather than hardcoding a list,
a *later* increment can add a role filter for roles that include (or can
assume) the permissions of a given role, e.g. "every role granting
`resourcemanager.organizations.setIamPolicy`". That composes with the same
policy instead of complicating this one, and is independently useful for other
controls.

It is deliberately separate work: predefined roles come from
`iam.roles.list` with an empty `parent`, but **organization custom roles come
from `organizations.roles.list`**, a different call. Permission equivalence
also needs each role's `includedPermissions` expanded. Worth doing, not worth
entangling with security keys.

### Known problem: iam-role enumerates the catalogue, not what's in use

`gcp.iam-role` has `scope = 'global'` and passes no `parent`, and `query.py`
only injects scope params for `project` and `zone`. So it lists the **2378
predefined roles**, which are identical for every customer, and excludes
organization custom roles entirely.

Consequences to work through before implementing:

- A name-matched policy returns `roles/resourcemanager.organizationAdmin`
  whether or not anybody in your organization holds it. Its computed user set
  would simply be empty, which yields no findings -- probably fine, but it
  means "compliant" and "role not used here" look alike.
- The organization IAM policy has to be read regardless, since that is the
  only place the role-to-user relationship exists.
- Custom roles being absent from the enumeration matters more once the
  permission-equivalence filter above exists, because a custom role granting
  org-admin permissions is exactly what it would want to catch.

## Superseded: what is a finding about?

Kept for the reasoning, since it explains why the role reading was chosen.

CIS 1.3 is a universally quantified claim: *for every admin account of this
organization, security key enforcement holds*. Reporting a violation of a
claim like that involves three different things, and the benchmark text does
not say which one a finding is meant to be:

| the claim is about | "it is compliant" reads as                      | a report row is       |
|--------------------|-------------------------------------------------|-----------------------|
| the organization   | this org enforces keys for all of its admins    | one org, pass or fail |
| the role binding   | every member of this admin role has enforcement | one role              |
| the account        | this admin account has enforcement              | one offending account |

Each reading has a real argument behind it:

- **The organization** is the only one of the three that genuinely *has* the
  compliance posture. Roles and accounts don't have a security posture with
  respect to a benchmark control; organizations do. It is also what an auditor
  signs off.
- **The role binding** is how the domain of the claim gets identified, and it
  is what CIS's audit procedure literally tells you to read. But a role is a
  permission bundle, identical in every organization; it isn't a bearer of
  posture. It is the enumeration mechanism rather than the subject.
- **The account** is the only one an operator can act on: you fix a finding by
  giving a person a security key, or by removing their admin binding.

So the requirement genuinely under-determines the resource, and that is a
workflow and reporting decision rather than something we can derive. Hence the
question to ask:

> Should a violation of CIS-B-GCPF-4.0.0-1.3 be reported as one row per
> offending admin account, or as one row per organization (or role) with the
> offending accounts attached?

Two things that make the answer matter more than it might appear:

- **The account reading can't be implemented by starting from accounts.** A
  policy over Workspace users inverts the population: it can only see managed
  users, so it would silently miss an external or federated principal holding
  organization admin -- precisely the case worth shouting about. Whatever the
  answer, the *evaluation* has to start from bindings.
- **A role is not a bearer of the property, and has no members.** Verified
  against the `iam` v1 discovery document: `Role` has exactly `name`, `title`,
  `description`, `includedPermissions`, `stage`, `deleted`, `etag`. No
  bindings, no principals, no organization. A role is a permission bundle
  definition, global and identical in every organization --
  `roles/resourcemanager.organizationAdmin` is the same object whether or not
  your org uses it -- so it cannot carry "is this organization compliant".
  `roles.list` enumerates the catalogue (2378 predefined roles) and knows
  nothing about who holds them. The thing that has members is the *binding*,
  which lives in the organization's IAM policy rather than in the role. Note
  also that `gcp.iam-role` already exists and means "the role catalogue", so
  reusing that concept for org-specific compliance would conflate two
  different notions.

## Deliberately not decided here

- Whether this is a new resource, a filter, or both.
- Which API is called, and therefore which OAuth scopes are declared.
- Whether the control is fully automatable, or whether the honest deliverable
  is a partial signal plus documentation of what remains manual.

## Likely change of test tenant

**Flagged so it can be forgotten until it matters.**

The first increment recorded against the Cloud Identity tenant for
`riversnake.com`, using a service account in the unrelated dev project
`stkl-jim-fulton` (which sits in the sixfeetup GCP organization). That worked
because domain-wide delegation doesn't care which project or org the service
account lives in.

This increment probably can't reuse that arrangement. It needs an
**organization IAM policy** containing a binding for a *test user*, and the
test users only exist as principals in the GCP organization that Cloud
Identity auto-provisioned for `riversnake.com`. Granting them anything in the
sixfeetup org is neither possible nor appropriate.

So expect to shift recording to the `riversnake.com` organization, which
implies:

- Confirming that org node actually exists and is materialised
  (`gcloud organizations list` while signed in as the workspace super admin).
  Cloud Identity provisions it, but it may need a first visit to the GCP
  console.
- A binding of the chosen admin role to a test user in that org.
- Credentials able to read that org's IAM policy: either the super admin's
  own ADC, or a new service account in a project inside that org. The
  existing `stkl-jim-fulton` service account is in the wrong org for this.
- Possibly accepting terms, and possibly billing, on first use of that org.

Note this is a second, distinct credential path from the workspace delegation
the first increment set up: org IAM read is ordinary GCP auth, not
domain-wide delegation. Whether a single policy run can hold both is part of
the design question above.
