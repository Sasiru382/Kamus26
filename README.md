# Kamus26
<!-- Modified in 2026 by Sasiru382. Changes are documented in Git history. -->

Kamus26 is an independently maintained derivative of [Soluto/Kamus](https://github.com/Soluto/kamus),
an open source, GitOps, zero-trust secrets encryption and decryption solution for Kubernetes applications.
This repository is maintained by [Sasiru382](https://github.com/Sasiru382); it is not an official
Soluto release and is not affiliated with or endorsed by Soluto. References to upstream projects,
packages, and documentation identify their origin, not an endorsement of Kamus26.

## Origin and licence

The original Kamus project is copyright 2019 Soluto and licensed under the
[Apache License 2.0](LICENSE). Kamus26 retains the upstream licence and attribution;
modified upstream files carry change notices. The original project and its contributors
retain credit for their work. This derivative is distributed under Apache 2.0.

Changes in this derivative include resilient Azure Key Vault support and a standalone
.NET decryption client. The upstream CRD controller has been removed. See the
[commit history](https://github.com/Sasiru382/Kamus26/commits/main/) for the changes.

## Overview
Kamus enable users to easily encrypt secrets than can be decrypted only by the application running on Kubernetes.
The encryption is done using strong encryption providers (currently supported: Azure KeyVault, Google Cloud KMS and AES).
To learn more about Kamus, check out the [blog post](https://blog.solutotlv.com/can-kubernetes-keep-a-secret?utm_source=github) and [slides](https://www.slideshare.net/SolutoTLV/can-kubernetes-keep-a-secret).
## Getting Started

The following commands install **upstream Kamus**, not Kamus26. To deploy this derivative,
configure the upstream chart to use your own Kamus26 images and disable the CRD controller,
as described below. The upstream chart is available with:
```
helm repo add soluto https://charts.soluto.io
helm upgrade --install kamus soluto/kamus
```
Refer to the [installation guide](https://kamus.soluto.io/docs/user/install/) for more details.
After installing Kamus, you can start using it to encrypt secrets.
Kamus encrypt secrets for a specific application, represent by a [Kubernetes Service Account](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account).
Create a service account for your application, and mount it on the pods running your application.
Now, when you know the name of the service account, and the namespace it exists in, install Kamus CLI:
```
npm install -g @soluto-asurion/kamus-cli
```
Use Kamus CLI to encrypt the secret:
```
kamus-cli encrypt --secret super-secret --service-account kamus-example-sa --namespace default --kamus-url <Kamus URL>
```
*If you're running Kamus locally the Kamus URL will be like `http://localhost:<port>`. So you need to add `--allow-insecure-url` flag to enable http protocol.* 

Pass the value returned by the CLI to your pod, and use Kamus Decrypt API to decrypt the value.
The simplest way to achieve that is by using the init container.
For .NET 8+ applications, use the standalone [Kamus.Decryption library](src/Kamus.Decryption/README.md)
to call the decrypt API from application code. It supports dependency injection and service-account token rotation.
To make it clearer, take a look on a working [example app](example/README.md).
You can deploy this app to any Kubernetes cluster that has Kamus installed, to understand how it works.

For questions about Kamus26, use this repository's [issue tracker](https://github.com/Sasiru382/Kamus26/issues).
The original Kamus documentation and community resources describe the upstream project.

## Architecture
Kamus has 3 components:
* Encrypt API
* Decrypt API
* Key Management System (KMS)

The encrypt and decrypt APIs handle encryption and decryption requests.
The KMS is a wrapper for various cryptographic solutions. Currently supported:
* AES - uses one key for all secrets
* AWS KMS, Azure KeyVault, Google Cloud KMS - creates one key per service account.

We look forward to add support for other cloud encryption backends.


Consult the [installation guide](https://kamus.soluto.io/docs/user/install) for more details on how to deploy Kamus using the relevant KMS.

### Utilities
Kamus is shipped with 3 utilities that make it easier to use:
* Kamus CLI - a small CLI that eases the interaction with the Encrypt API. Refer to the [docs](https://github.com/Soluto/kamus/blob/master/cli/README.md) for more details.
* Kamus init container - a init container that interacts with the Decrypt API. Refer to the [docs](https://github.com/Soluto/kamus/blob/master/init-container/README.md) for more details.
* [Kamus.Decryption](src/Kamus.Decryption/README.md) - a standalone NuGet library for decryption inside .NET applications.

This branch no longer includes the Kamus CRD controller or support for reconciling `KamusSecret`
resources into Kubernetes Secrets. Existing installations must migrate workloads that rely on
that feature before removing their deployed controller. This code change does not uninstall
anything from a cluster. Upstream Helm charts are separate projects; configure them to disable
the controller and use this branch's API images when deploying this version.

## Upstream users
* [1 Giant Leap Solutions](https://1giantleap.nl/)
* [UK Hydrographic Office](https://www.ukho.gov.uk/)

These organisations are listed in the upstream Kamus README; this is not a claim that they use or endorse Kamus26.

## Security
The inherited [threat-model documentation](site/content/docs/threatmodeling/) describes
upstream Kamus security considerations. It is not a security certification of Kamus26.
Before installing Kamus in production refer to the installation guide to learn the best practices of deploying Kamus securely.
The inherited [security.md](security.md) policy lists Soluto's upstream reporting address;
it is not a Kamus26 support contact. For a Kamus26-specific vulnerability, contact
the maintainer privately before disclosing details. Do not post credentials or
vulnerability details in a public issue.

## Contributing
Kamus26-specific bug reports and contributions belong in
[this repository](https://github.com/Sasiru382/Kamus26), not the upstream issue tracker.
Please do not report security vulnerabilities in public GitHub issues.
