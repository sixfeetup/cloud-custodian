Workspace Users - find users without MFA
========================================

Google Workspace (Cloud Identity) users are not GCP resources. They are read
through the Admin SDK Directory API, which differs from the rest of the GCP
provider in two ways: it is scoped to a Workspace *customer* rather than a
project, and it is authorized by domain wide delegation rather than by GCP
IAM.

Setup
-----

You need a service account that a Workspace super administrator has
authorized for the ``admin.directory.user.readonly`` scope, and a Workspace
admin for it to impersonate. The impersonated user needs only the
``Users > Read`` privilege, not super admin.

``GOOGLE_APPLICATION_CREDENTIALS``
  Service account key file. A key is required because delegation self signs
  a JWT.

``GOOGLE_WORKSPACE_SUBJECT``
  The Workspace admin to impersonate. Delegation is only attempted when this
  is set.

``GOOGLE_WORKSPACE_CUSTOMER``
  Optional customer id. Defaults to ``my_customer``, meaning the customer of
  the impersonated subject.

A run targets one customer, so scanning several means several runs. Because
the resource is customer scoped rather than project scoped, it should be
excluded from per project sweeps, which would otherwise report the same
users once per project.

Finding users without MFA
-------------------------

The Directory API reports 2 step verification, Google's term for MFA, per
user. This satisfies CIS-B-GCPF-4.0.0-1.2. Suspended users cannot sign in,
so they are excluded to avoid noise.

.. code-block:: yaml

    policies:
      - name: gcp-workspace-users-without-mfa
        description: |
          Workspace users that have not enrolled in 2 step verification.
        resource: gcp.workspace-user
        filters:
          - type: value
            key: isEnrolledIn2Sv
            value: false
          - type: value
            key: suspended
            value: false

Caveats
-------

``isEnrolledIn2Sv`` and ``isEnforcedIn2Sv`` report whether a second factor is
present or required, not which type it is. The Directory user resource does
not expose security key information, so security key enforcement cannot be
audited through this resource.

``isAdmin`` denotes a Workspace *super* administrator. Administrators holding
a narrower delegated role appear as ``isDelegatedAdmin`` instead, and neither
is the same as a GCP ``roles/resourcemanager.organizationAdmin`` binding.

If your organization authenticates through an external identity provider,
MFA may be enforced there rather than by Google, in which case
``isEnrolledIn2Sv`` can read false for users who are in fact strongly
authenticated.
