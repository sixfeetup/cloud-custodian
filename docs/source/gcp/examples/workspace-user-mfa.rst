Workspace Users - find users without MFA
========================================

Google Workspace (Cloud Identity) users are not GCP resources. They are read
through the Admin SDK Directory API, which differs from the rest of the GCP
provider in two ways: it is scoped to a Workspace *customer* rather than a
project, and it is authorized by domain wide delegation rather than by GCP
IAM.

A *customer* is a Workspace / Cloud Identity account, the tenant that owns
the users. It plays the role that a project plays for GCP resources, and is
identified by an opaque id such as ``C03abc123``.

How the pieces fit together
---------------------------

The service account lives in a GCP project. The users, and the admin whose
privileges are borrowed to read them, live in the Workspace customer. The two
are connected by an entry in the Workspace Admin console, not by any GCP
relationship, so the service account can live in any project::

    1. Custodian authenticates as the service account   [GCP project]
                       |
                       |  GOOGLE_APPLICATION_CREDENTIALS=<key file>
                       v
    2. asking to act as the admin user             [Workspace customer]
                       |
                       |  GOOGLE_WORKSPACE_SUBJECT=admin@your-domain
                       |
                       |  permitted because the Admin console authorizes
                       |  this service account's client id for the
                       |  admin.directory.user.readonly scope, and the
                       |  admin holds the Users > Read privilege
                       v
    3. and lists the users of a customer          [Admin SDK Directory API]
                       |
                       |  customer=my_customer, an alias for the customer
                       |  the impersonated admin belongs to
                       v
              gcp.workspace-user resources

The service account is only ever the means of authenticating. It holds no
Workspace privileges itself; every call is made as the impersonated admin.

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
  Optional customer id. Defaults to ``my_customer``, which resolves to the
  customer the impersonated subject belongs to, so the usual single tenant
  case needs no configuration. Set it when the subject can administer more
  than one customer, or to pin the target explicitly.

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
