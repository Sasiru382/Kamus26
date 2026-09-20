# Deny Kuberentes secrets view permissions
<!-- Modified in 2026 by Sasiru382. These independently authored changes are documented in Git history. -->

Feature: Deny Kuberentes secrets view permissions
  In order to protect Kamus from DoS
  As a cluster admin
  I want to deny all users from getting Kubernetes secrets in all namespaces

  Scenario: Using Kubernetes RBAC
    Given a user role without secrets get permissions 
    When the user try to read service account's secret
    Then the operation denied


## Remarks

* Mitigates: 
 * [Impersonating pod to decrypt it's secrets](/docs/threatmodeling/threats/decryption/pod_impersonation)
* References:
 * https://kubernetes.io/docs/reference/access-authn-authz/rbac/

Back to [Threats and Controls](/docs/threatmodeling/threats_controls)
