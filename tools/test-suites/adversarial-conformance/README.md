# Design Note: Adversarial Conformance Testing and Fixture Structure for Offline Verification

**Author:** Zachary Kietzman (AuthiChain)
**Status:** Draft / Proposed Contribution to W3C VSC CG Repository
**Target:** Open standard conformance, test suites, and interoperability criteria

*This design note is informative. The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as described in BCP 14 ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when they appear in all capitals. Here they describe requirements proposed for a future conformance test suite.*

## 1. Overview and Motivation

Verifiable supply chains and Digital Product Passports (DPPs) often rely on assumptions of continuous network connectivity or centralized trust registries. However, real-world supply chain verification—particularly at border checkpoints, recycling facilities, and disconnected retail nodes—frequently occurs with limited or no network connectivity.

Furthermore, traditional conformance suites test only the happy path, allowing subtly broken or non-compliant implementations to pass silently if they avoid throwing unhandled exceptions.

This design note proposes an adversarial conformance model built on:

- Deliberately broken and malformed implementation fixtures to test parser and validator resilience.
- Strict reason checking (machine-readable failure codes rather than generic errors).
- Explicit ternary verdict semantics with zero numeric scoring.
- Strict offline verification, in which the verifier makes no network requests at verification time and relies only on locally supplied context (trust anchors, keys, and status information).

## 2. Core Principles

**Ternary Verdicts:** Verifiers MUST return exactly one of three states:

- `VALID`: All cryptographic proofs, schema requirements, and supply-chain continuity checks succeed.
- `INVALID`: A definitive cryptographic, structural, or policy violation occurred.
- `INDETERMINATE`: Insufficient verifiable context available locally (e.g., missing offline trust anchor root), preventing a definitive pass/fail.

Verifiers MUST NOT return numeric scores (e.g., 85/100) in place of a verdict, as they obscure actionable compliance failures.

**Strict Reason Codes:** Every non-VALID outcome MUST be accompanied by a standardized, machine-readable reason code (e.g., `ERR_CREDENTIAL_EXPIRED`, `ERR_SIGNATURE_EXPIRED`, `ERR_REVOCATION_STATUS_UNKNOWN`). Schema violations SHOULD follow the naming pattern `ERR_SCHEMA_VIOLATION_<FIELD>`; `ERR_SCHEMA_VIOLATION_FIELD_X` is an illustration of that pattern, not a defined code.

`ERR_CREDENTIAL_EXPIRED` means the credential's validity window (`validUntil`) has passed. `ERR_SIGNATURE_EXPIRED` means the proof or its verification key is expired even though the credential itself may still be valid.

**Adversarial Test Fixtures:** Conformance test runners validate verifier implementations against standardized JSON/JSON-LD bundles containing edge-case corruption (e.g., expired timestamps, mismatched supply-chain predecessor links, altered payloads, and truncated chains).

## 3. Fixture Schema Specification

A conformance fixture is packaged as a JSON document containing the test metadata, the input verifiable credential / supply-chain packet, and the expected verifier outcome. The examples use the [Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) and a Data Integrity proof with the [`eddsa-rdfc-2022`](https://www.w3.org/TR/vc-di-eddsa/) cryptosuite.

> **Proposed placeholders:** `https://w3id.org/vsc/conformance/v1/fixture.schema.json` and `https://w3id.org/vsc/v1` are proposed placeholder URLs. They are not registered and do not resolve yet.
>
> **Illustrative values:** the shortened `did:key` identifiers and `proofValue` strings (shown with `...`) are illustrative only. Real fixtures would carry complete keys and valid or deliberately corrupted signatures.

Example Fixture Structure (`fixture-vsc-001.json`):

```json
{
  "$schema": "https://w3id.org/vsc/conformance/v1/fixture.schema.json",
  "testId": "VSC-ADV-042",
  "description": "Reject credential with an expired validity window under strict offline mode",
  "profile": "offline-strict",
  "input": {
    "credential": {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/vsc/v1"
      ],
      "id": "urn:uuid:6ba7b810-9dad-11d1-80b4-0c0411d3047a",
      "type": ["VerifiableCredential", "DigitalProductPassportCredential"],
      "issuer": "did:key:z6MksH1...",
      "validFrom": "2024-01-01T00:00:00Z",
      "validUntil": "2025-01-01T00:00:00Z",
      "credentialSubject": {
        "id": "urn:epcid:sgtin:0614141.107346.2017",
        "batchNumber": "B-99887",
        "predecessorHash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      },
      "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-rdfc-2022",
        "created": "2024-01-01T00:05:00Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6MksH1...#z6MksH1...",
        "proofValue": "z3u7...abc"
      }
    },
    "environment": {
      "currentTimestamp": "2026-09-25T00:00:00Z",
      "allowNetworkAccess": false
    }
  },
  "expected": {
    "verdict": "INVALID",
    "reasonCode": "ERR_CREDENTIAL_EXPIRED",
    "strictReasonMatch": true
  }
}
```

Example INDETERMINATE fixture (`fixture-vsc-002.json`). The credential is within its validity window and references a revocation status list, but no copy of that list is supplied locally and network access is disallowed, so the verifier cannot reach a definitive pass/fail:

```json
{
  "$schema": "https://w3id.org/vsc/conformance/v1/fixture.schema.json",
  "testId": "VSC-ADV-043",
  "description": "Return INDETERMINATE when revocation status cannot be checked under strict offline mode",
  "profile": "offline-strict",
  "input": {
    "credential": {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://w3id.org/vsc/v1"
      ],
      "id": "urn:uuid:3f1c2a9e-5b7d-4e8a-9c21-7d4b0e6f1a52",
      "type": ["VerifiableCredential", "DigitalProductPassportCredential"],
      "issuer": "did:key:z6MksH1...",
      "validFrom": "2026-01-01T00:00:00Z",
      "validUntil": "2027-01-01T00:00:00Z",
      "credentialStatus": {
        "id": "https://status.example/lists/1#94567",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "revocation",
        "statusListIndex": "94567",
        "statusListCredential": "https://status.example/lists/1"
      },
      "credentialSubject": {
        "id": "urn:epcid:sgtin:0614141.107346.2018",
        "batchNumber": "B-99888"
      },
      "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-rdfc-2022",
        "created": "2026-01-01T00:05:00Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:key:z6MksH1...#z6MksH1...",
        "proofValue": "z4k9...def"
      }
    },
    "environment": {
      "currentTimestamp": "2026-09-25T00:00:00Z",
      "allowNetworkAccess": false,
      "localStatusLists": []
    }
  },
  "expected": {
    "verdict": "INDETERMINATE",
    "reasonCode": "ERR_REVOCATION_STATUS_UNKNOWN",
    "strictReasonMatch": true
  }
}
```

`environment.localStatusLists` is an array of status list credentials supplied to the verifier in advance; when `allowNetworkAccess` is `false`, these are the only status lists the verifier may consult, and an empty array means none are available.

## 4. Conformance Test Suite Workflow

1. **Test Runner Initialization:** The conformance test suite loads the library of adversarial fixtures (`/fixtures/*.json`).
2. **Execution:** The target verifier implementation processes each fixture under the specified environmental constraints (`allowNetworkAccess: false`).
3. **Assertion:** The test runner evaluates:
   - Did the verdict match the expected ternary state (`VALID`, `INVALID`, `INDETERMINATE`)?
   - Does the returned `reasonCode` match the expected standardized string code?
4. **Reporting:** Generates an interoperability matrix showing adherence to the VSC baseline specification.

The interoperability matrix SHOULD be published as JSON, with one row per implementation and one cell per `testId`. Each cell records the returned verdict and reason code and a result of `pass` (both match the fixture) or `fail`. For example:

```json
{
  "suite": "vsc-adversarial-conformance",
  "implementations": [
    {
      "name": "example-verifier",
      "version": "0.1.0",
      "results": {
        "VSC-ADV-042": { "verdict": "INVALID", "reasonCode": "ERR_CREDENTIAL_EXPIRED", "result": "pass" },
        "VSC-ADV-043": { "verdict": "INVALID", "reasonCode": "ERR_REVOCATION_STATUS_UNKNOWN", "result": "fail" }
      }
    }
  ]
}
```

An HTML or Markdown table MAY be generated from this JSON for readability.

## 5. Next Steps for the CG

- Review and adopt the JSON schema for test fixtures in the `w3c-cg/vsc` repository.
- Populate initial test vectors covering common supply chain failure modes (revoked roots, broken chain hashes, clock skew).
- Integrate into the `tools/test-suites/` workstream.
