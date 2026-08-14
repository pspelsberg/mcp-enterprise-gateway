# Sandbox image provenance and SBOM gate

The gateway never pulls sandbox images. Enterprise deployments must configure
`MCP_PYTHON_IMAGE` and `MCP_NODE_IMAGE` as immutable `repository@sha256:<64 hex>`
references and may additionally configure `expected_image_ids` in deployment
code. The default zero digests are intentionally non-runnable fail-closed
placeholders.

Before loading an image into the Docker daemon, the release pipeline must:

1. resolve the digest from the approved registry;
2. verify the image signature/attestation with the organization-approved
   Sigstore/Notary policy;
3. archive the corresponding SPDX or CycloneDX SBOM and vulnerability result;
4. review digest rotation as a code change; and
5. run the sandbox security regression suite.

Runtime only verifies the immutable reference and locally reported
`RepoDigests`/optional image ID. It performs no network verification and no
automatic pull. Image provenance and SBOM evidence are deployment release
artifacts, not MCP client data.
