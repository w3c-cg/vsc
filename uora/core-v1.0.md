
# Universal Object & Resource Attestation (UORA) Core Protocol v1.0

**Identifier:** `https://w3id.org/uora/spec/core/v1.0`
**Status:** Working Draft — Call for Consensus
**Editors:** Amir Hameed Mir

---

## 0. Version History

| Version | Date | Changes |
|---|---|---|
| v0.1 | 2026-04-28 | Initial architecture draft |
| v1.0 | 2026-04-28 | Governance, Query API, Antecedent Chaining, Conformance Suite |

---

## 1. Abstract

The Universal Object & Resource Attestation (UORA) Protocol defines a complete, vendor-neutral framework for decentralized identity, state verification, and lifecycle tracking of physical assets across untrusted parties. Unlike data-format specifications that define only syntax, UORA defines a **protocol**: a set of rules for how attestations are issued, discovered, validated, and reconciled.

This specification addresses the four pillars of decentralized supply chain trust:

1. **Governance & Authorization (§4):** A verifiable chain of authority ensuring that only certified entities may issue specific attestation types for specific product categories, through decoupled `CertificationCredential`s that enable industry-specific Trust Frameworks without modifying the core protocol.

2. **Standardized Discovery (§3.3):** The UORA-Query-API, a uniform HTTP protocol that eliminates API fragmentation by mandating a single, standardized endpoint structure and response format for retrieving attestation history from any Resolver.

3. **Deterministic State Reconciliation (§5.1):** A cryptographically linked "antecedent chain" supporting both linear sequences and Directed Acyclic Graphs (DAGs), with a mathematically verifiable conflict resolution cascade (`validFrom` timestamp → issuer authority → attestation ID hash) that eliminates the need for external consensus mechanisms. Linear custody chains are enforced: Transfer and Disposition attestations MUST reference the most recent valid event in the chain.

4. **Conformance & Testability (§7):** A mandatory compliance test suite with 22 test vectors across five categories, defining three conformance levels (`Data`, `Protocol`, `Full`) that provide unambiguous, machine-verifiable criteria for implementation correctness.

By defining not merely the *data model* but the *resolution rules*, UORA enables fully automated, legally defensible verification of physical asset provenance, custody, and compliance across organizational and jurisdictional boundaries.

---

## 2. Architecture

### 2.1 The UORA Trust Stack

```
┌──────────────────────────────────────────────────┐
│  Layer 4: Domain Profiles                         │
│  (Verifiable Supply Chain, Pharma, Critical       │
│   Minerals, Food & Beverage)                      │
│  → Extends UORAAttestation subtypes               │
│  → Adds industry-specific claims                  │
├──────────────────────────────────────────────────┤
│  Layer 3: Governance & Authorization              │
│  (CertificationCredentials, Trust Frameworks)     │
│  → Decoupled from core attestation schema         │
│  → Industry-specific without protocol modification│
├──────────────────────────────────────────────────┤
│  Layer 2: Core Attestation Schemas                │
│  (Origin, Transfer, Transformation, Disposition)  │
│  → Antecedent Chaining (Linear + DAG)             │
│  → Deterministic Conflict Resolution              │
│  → Linear Custody Chain Enforcement               │
├──────────────────────────────────────────────────┤
│  Layer 1: Universal Object Addressing & Discovery │
│  (DID Method binding, UORA-Query-API)             │
│  → Standardized object identification             │
│  → Uniform history retrieval protocol             │
└──────────────────────────────────────────────────┘
```

### 2.2 Protocol Roles

| Role | Definition |
|---|---|
| **Issuer** | Entity that creates and cryptographically signs attestations. MUST possess a valid `CertificationCredential` for the specific attestation type and product category. |
| **Holder** | Entity possessing the physical object and its attestation chain. May present attestations to Verifiers. |
| **Verifier** | Entity that validates attestations using the governance rules (§4), antecedent chain integrity (§5.1), linear custody enforcement (§5.1.4), and conflict resolution cascade (§5.1.3) defined herein. |
| **Trust Anchor** | Governance body that issues `CertificationCredential`s to legitimate Issuers according to a published Trust Framework. |
| **Resolver** | Service implementing the UORA-Query-API (§3.3) for standardized attestation discovery and history retrieval. |

---

## 3. Universal Object Addressing & Discovery (Layer 1)

### 3.1 DID Method for Physical Objects

Every physical object tracked by UORA SHALL be assigned a Decentralized Identifier resolvable to a DID Document containing:

- Cryptographic verification material
- A `service` endpoint conforming to the UORA-Query-API protocol (§3.3)
- Physical binding metadata (§3.4)

**DID Pattern:**
```
did:web:{domain}:object:{granularity}:{identifier}
```

**Identification Granularity:**

| Level | Example DID | Use Case |
|---|---|---|
| Serial | `did:web:maker.example.com:object:serial:SN-001` | Individual item tracking |
| Batch/Lot | `did:web:maker.example.com:object:lot:L-2026-04` | Batch-level traceability |
| SKU/Class | `did:web:maker.example.com:object:sku:GTIN-123456` | Product class identification |

### 3.2 DID Document Structure

A UORA-compliant DID Document SHALL include:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:maker.example.com:object:serial:SN-001",
  "verificationMethod": [
    {
      "id": "#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:maker.example.com:object:serial:SN-001",
      "publicKeyMultibase": "zH3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    }
  ],
  "assertionMethod": ["#key-1"],
  "service": [
    {
      "id": "#attestation-history",
      "type": "UORAAttestationService",
      "serviceEndpoint": "https://maker.example.com/uora/v1"
    }
  ]
}
```

### 3.3 UORA-Query-API Protocol

To eliminate API fragmentation, every UORA-compliant Resolver SHALL implement this standardized query interface at the `serviceEndpoint` declared in the object's DID Document.

#### 3.3.1 Endpoints

```
GET  {serviceEndpoint}/history     # Query attestation history
POST {serviceEndpoint}/attestations # Capture and validate new attestation
POST {serviceEndpoint}/validate    # Validate without storing  
GET  {serviceEndpoint}/health      # Health check
GET  {serviceEndpoint}/stats       # Store statistics
GET  {serviceEndpoint}/chain       # Display custody chain timeline
```

#### 3.3.2 Request Parameters for /history

| Parameter | Required | Type | Description |
|---|---|---|---|
| `did` | MUST | URI | The DID of the physical object |
| `eventType` | OPTIONAL | String | Filter by attestation type: `Origin`, `Transfer`, `Transformation`, `Disposition` |
| `from` | OPTIONAL | ISO 8601 | Return attestations with `validFrom >= from` |
| `to` | OPTIONAL | ISO 8601 | Return attestations with `validFrom <= to` |
| `limit` | OPTIONAL | Integer | Maximum results (default: 100, max: 1000) |

#### 3.3.3 Response Format

**Success (200 OK) for /history:**

```json
{
  "did": "did:web:maker.example.com:object:serial:SN-001",
  "attestations": [
    {
      "id": "urn:uuid:origin-attestation-id",
      "type": ["VerifiableCredential", "UORAAttestation", "UORAOriginAttestation"],
      "validFrom": "2026-01-15T08:00:00Z",
      "issuer": "did:web:maker.example.com",
      "eventType": "Origin",
      "antecedent": null,
      "status": "valid",
      "chainIntegrity": "intact",
      "supersededBy": null,
      "proof": { /* Data Integrity Proof */ },
      "credential": { /* full verifiable credential */ }
    },
    {
      "id": "urn:uuid:transfer-attestation-id",
      "type": ["VerifiableCredential", "UORAAttestation", "UORATransferAttestation"],
      "validFrom": "2026-04-28T10:30:00Z",
      "issuer": "did:web:shipper.example.com",
      "eventType": "Transfer",
      "antecedent": ["urn:uuid:origin-attestation-id"],
      "status": "valid",
      "chainIntegrity": "intact",
      "supersededBy": null,
      "proof": { /* Data Integrity Proof */ },
      "credential": { /* full verifiable credential */ }
    }
  ],
  "total": 2
}
```

**Success (201 Created) for POST /attestations:**

```json
{
  "status": "accepted",
  "attestationId": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
  "chainIntegrity": "intact",
  "eventType": "Transfer",
  "antecedent": ["urn:uuid:origin-attestation-id"]
}
```

**Success (200 OK) for POST /validate:**

```json
{
  "status": "valid",
  "error": null,
  "chainIntegrity": "intact",
  "details": {
    "attestationId": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
    "issuer": "did:web:shipper.example.com",
    "eventType": "Transfer",
    "antecedent": ["urn:uuid:origin-attestation-id"],
    "proofType": "Ed25519Signature2020"
  }
}
```

**Success (200 OK) for GET /chain:**

```json
{
  "did": "did:web:maker.example.com:object:serial:SN-001",
  "chainLength": 3,
  "isComplete": false,
  "chain": [
    {
      "position": 1,
      "eventType": "Origin",
      "attestationId": "urn:uuid:origin-attestation-id",
      "timestamp": "2026-01-15T08:00:00+00:00",
      "issuer": "did:web:maker.example.com",
      "description": "Object created at https://id.gs1.org/414/9521321000010"
    }
  ]
}
```

**Error Responses:**

| Status | Condition |
|---|---|
| 400 | Missing required `did` parameter or invalid JSON |
| 404 | DID not found or no attestation history available |
| 409 | Duplicate attestation ID |
| 422 | Validation failure (attestation rejected) |
| 500 | Internal resolver error |

### 3.4 Secure Physical Binding

A UORA digital identity MUST be bound to its physical counterpart through at least one tamper-evident mechanism.

| Mechanism | Security Level | Typical Application |
|---|---|---|
| Cryptographic NFC Tag | High | Individual high-value items |
| Secure QR with Digital Signature | Medium | Batch-level tracking |
| IoT Hardware Security Module (HSM) | High | Containers, vehicles, equipment |
| Physically Unclonable Function (PUF) | Very High | Critical components, luxury goods |

The binding SHALL be verifiable through possession proof (challenge-response with the physical object) and cryptographic verification against the DID Document's `verificationMethod`.

---

## 4. Governance & Authorization (Layer 3)

### 4.1 Certification of Authority

An attestation SHALL NOT be considered valid unless the Issuer possesses a valid **Certification of Authority** (`UORACertificationCredential`) for the specific attestation type and product category.

#### 4.1.1 CertificationCredential Schema

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/uora/contexts/core.jsonld"
  ],
  "id": "urn:uuid:cert-credential-id",
  "type": ["VerifiableCredential", "UORACertificationCredential"],
  "issuer": {
    "id": "did:web:trust-anchor.example.com",
    "name": "Pharmaceutical Trust Anchor Consortium"
  },
  "validFrom": "2026-01-01T00:00:00Z",
  "validUntil": "2027-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:web:certified-issuer.example.com",
    "authorizedAttestations": [
      "UORAOriginAttestation",
      "UORATransferAttestation",
      "UORATransformationAttestation"
    ],
    "authorizedCategories": [
      "pharmaceuticals",
      "medical-devices"
    ],
    "authorizedRegions": ["global"],
    "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1"
  }
}
```

#### 4.1.2 authorizedBy Claim

Every `UORAAttestation` MUST include an `authorizedBy` claim referencing a valid `UORACertificationCredential`:

```json
{
  "credentialSubject": {
    "authorizedBy": {
      "certificationId": "urn:uuid:cert-credential-id",
      "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
      "verifiedAt": "2026-04-28T10:30:00Z"
    }
  }
}
```

#### 4.1.3 Validation Rules

A Verifier SHALL reject any attestation where:

1. The `authorizedBy` claim is absent (status: `rejected_missing_authorization`)
2. The referenced `certificationId` cannot be resolved to a valid, unexpired `UORACertificationCredential` (status: `rejected_unauthorized_issuer`)
3. The attestation's `validFrom` timestamp falls outside the `validFrom`/`validUntil` window of the certification (status: `rejected_expired_certification`)
4. The attestation's `type` is not present in the certification's `authorizedAttestations` (status: `rejected_unauthorized_category`)
5. The issuer's DID does not match the certification's `credentialSubject.id` (status: `rejected_unauthorized_issuer`)

---

## 5. Core Attestation Schemas (Layer 2)

### 5.1 Antecedent Chaining & Deterministic State Reconciliation

Every UORA attestation SHALL reference its immediate predecessor through an `antecedent` property, creating a cryptographically linked, verifiable history chain. This enables automated conflict resolution without external consensus mechanisms.

#### 5.1.1 Linear Chains

For events where history is sequential (single custody transfers, simple observations):

```json
{
  "credentialSubject": {
    "antecedent": "urn:uuid:previous-attestation-id"
  }
}
```

The implementation normalizes single antecedent strings to arrays: `["urn:uuid:previous-attestation-id"]`.

The first attestation in an object's lifecycle SHALL have `"antecedent": null`.

#### 5.1.2 Directed Acyclic Graph (DAG) Support

For **transformations** and **aggregations** where multiple inputs converge into one output, or one input diverges into multiple outputs, `antecedent` SHALL accept an ordered array of attestation IDs:

```json
{
  "credentialSubject": {
    "antecedent": [
      "urn:uuid:component-a-final-state",
      "urn:uuid:component-b-final-state",
      "urn:uuid:component-c-final-state"
    ]
  }
}
```

**DAG Validation Rule:** For any attestation with a DAG antecedent, the Verifier SHALL recursively validate the integrity of every branch. The attestation is valid only if ALL antecedent branches resolve to valid terminal states.

#### 5.1.3 Conflict Resolution Cascade

If a Verifier encounters two attestations claiming to succeed the same antecedent, the conflict SHALL be resolved using this deterministic cascade:

| Priority | Rule | Description |
|---|---|---|
| **1 (Highest)** | Timestamp Precedence | The attestation with the later `validFrom` timestamp prevails. Uses 1-second tolerance for timestamp equality. |
| **2** | Authority Precedence | If timestamps are identical (within 1-second tolerance), the attestation from the Issuer with higher precedence in the applicable Trust Framework prevails. |
| **3 (Lowest)** | Hash Precedence | If both timestamp and authority are equal, the attestation with the lexicographically smaller `id` prevails. |

**Authority Precedence Configuration:**

Trust Framework authority is configured with numeric precedence values where higher integers indicate higher authority:

```json
{
  "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1": {
    "did:web:fda.example.gov": 100,
    "did:web:manufacturer.example.com": 50,
    "did:web:wholesaler.example.com": 30
  },
  "https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1": {
    "did:web:carrier.example.com": 50,
    "did:web:warehouse.example.com": 40
  }
}
```

**Preservation:** The losing attestation SHALL be preserved in history for auditability with `"status": "superseded"` and `"supersededBy"` set to the winning attestation's ID. Superseded attestations SHALL NOT be used for state computation.

#### 5.1.4 Linear Custody Chain Enforcement

For Transfer and Disposition attestations, the Verifier SHALL enforce linear custody chain integrity. The `antecedent` MUST reference the **most recent valid event** for the subject object. This prevents gaps in the custody timeline and ensures a complete audit trail.

**Validation Rule:** If a Transfer or Disposition attestation references an antecedent that is not the most recent VALID attestation in the object's history, the attestation SHALL be rejected with status `rejected_linear_chain_violation`.

Origin events (antecedent: null) and Transformation events (multi-antecedent DAG) are exempt from linear chain enforcement.

### 5.2 UORAAttestation (Abstract Base Type)

All UORA attestations SHALL extend this abstract base type.

**Mandatory Type Chain:**
```
["VerifiableCredential", "UORAAttestation", "<concrete-type>"]
```

**Base Properties:**

| Property | Required | Type | Description |
|---|---|---|---|
| `@context` | MUST | Array | VC v2 context + UORA Core context |
| `type` | MUST | Array | Full type chain including `UORAAttestation` + exactly one concrete type |
| `id` | MUST | URI | Unique attestation identifier (UUID URN) |
| `issuer.id` | MUST | URI | DID of the certified Issuer |
| `validFrom` | MUST | DateTime | ISO 8601 timestamp of the attested event |
| `credentialSubject.id` | MUST | URI | DID of the physical object |
| `credentialSubject.eventType` | MUST | String | `Origin`, `Transfer`, `Transformation`, or `Disposition` |
| `credentialSubject.antecedent` | MUST | URI, Array, or null | Predecessor attestation ID(s) |
| `credentialSubject.authorizedBy` | MUST | Object | Certification reference per §4.1.2 |
| `evidence` | MUST | Array | At least one evidence entry per §5.7 |
| `proof` | MUST | Object | W3C Data Integrity Proof per §5.8 |

### 5.3 UORAOriginAttestation

Documents the creation, manufacture, mining, or harvest of a physical object.

**Concrete Type:** `["VerifiableCredential", "UORAAttestation", "UORAOriginAttestation"]`

**Additional Claims:**

| Property | Required | Type | Description |
|---|---|---|---|
| `originType` | MUST | String | `manufactured`, `mined`, `harvested`, or `created` |
| `originLocation` | MUST | URI | Physical location of origin |
| `originDate` | MUST | DateTime | Timestamp of creation |
| `productionBatch` | OPTIONAL | String | Batch or lot identifier |
| `inputMaterials` | OPTIONAL | Array | DID references to source materials |

**Antecedent:** SHALL be `null` for origin events. Origin attestations with non-null antecedent SHALL be rejected.

### 5.4 UORATransferAttestation

Documents a change of custody, ownership, or physical location.

**Concrete Type:** `["VerifiableCredential", "UORAAttestation", "UORATransferAttestation"]`

**Additional Claims:**

| Property | Required | Type | Description |
|---|---|---|---|
| `transferType` | MUST | String | `custody`, `ownership`, or `location` |
| `fromParty` | MUST | URI | DID of transferring party |
| `toParty` | MUST | URI | DID of receiving party |
| `fromLocation` | OPTIONAL | URI | Origin location |
| `toLocation` | OPTIONAL | URI | Destination location |

**Antecedent:** SHALL reference the most recent valid event per §5.1.4 (Linear Custody Chain Enforcement).

### 5.5 UORATransformationAttestation

Documents processing, assembly, or modification of objects into new outputs.

**Concrete Type:** `["VerifiableCredential", "UORAAttestation", "UORATransformationAttestation"]`

**Additional Claims:**

| Property | Required | Type | Description |
|---|---|---|---|
| `transformationType` | MUST | String | `assembly`, `processing`, `modification`, or `disassembly` |
| `inputObjects` | MUST | Array | DID references to input objects |
| `outputObjects` | MUST | Array | DID references to resulting objects |
| `inputQuantities` | OPTIONAL | Array | Quantity of each input consumed |
| `outputQuantities` | OPTIONAL | Array | Quantity of each output produced |
| `transformationLocation` | OPTIONAL | URI | Where transformation occurred |
| `processCertification` | OPTIONAL | URI | Reference to process certification |

**Antecedent:** SHALL be an array of attestation IDs for each `inputObject`. Must contain at least one entry (DAG chain).

### 5.6 UORADispositionAttestation

Documents the end-of-life, recycling, or decommissioning of an object.

**Concrete Type:** `["VerifiableCredential", "UORAAttestation", "UORADispositionAttestation"]`

**Additional Claims:**

| Property | Required | Type | Description |
|---|---|---|---|
| `dispositionType` | MUST | String | `recycled`, `decommissioned`, `destroyed`, or `lost` |
| `dispositionLocation` | OPTIONAL | URI | Where disposition occurred |
| `environmentalCertification` | OPTIONAL | URI | Environmental compliance reference |

**Antecedent:** SHALL reference the most recent valid event per §5.1.4 (Linear Custody Chain Enforcement).

### 5.7 Evidence & Data Economy

#### 5.7.1 Required Evidence

Every attestation MUST include at least one `evidence` entry:

```json
{
  "evidence": [
    {
      "id": "urn:uuid:evidence-unique-id",
      "type": ["Evidence"],
      "name": "Human-readable evidence name",
      "description": "Description of the evidence"
    }
  ]
}
```

#### 5.7.2 EPCIS Evidence Linking

Attestations MAY link to GS1 EPCIS events for supply chain traceability. EPCIS-linked evidence includes additional fields:

```json
{
  "evidence": [
    {
      "id": "urn:uuid:evidence-unique-id",
      "type": ["Evidence", "EPCISObjectEvent"],
      "name": "EPCIS Shipping Event",
      "description": "Original EPCIS ObjectEvent with bizStep=shipping",
      "epcisEventID": "ni:///sha-256;abc123def456?ver=CBV2.0",
      "epcisEventType": "ObjectEvent",
      "epcisBizStep": "shipping"
    }
  ]
}
```

Supported EPCIS event types in evidence: `EPCISObjectEvent`, `EPCISAggregationEvent`, `EPCISTransactionEvent`, `EPCISTransformationEvent`, `EPCISAssociationEvent`.

#### 5.7.3 Data Economy Guidelines (Informative)

To prevent evidence bloat, implementations SHOULD reference large external payloads via URI rather than embedding them directly.

| Data Size | Recommendation |
|---|---|
| < 1 KB | Embed directly in `evidence` |
| 1 KB – 1 MB | Reference via `externalData` object with `uri`, `hash` (SHA-256), and `size` |
| > 1 MB | Always reference via `externalData` object |

**Content-Addressable References:**

```json
{
  "externalData": {
    "uri": "https://storage.example.com/report-001.pdf",
    "hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "size": 1048576
  }
}
```

### 5.8 Proof Section

#### 5.8.1 Data Integrity Proof

Every UORA attestation MUST carry a W3C Data Integrity Proof for cryptographic verifiability:

```json
{
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-04-28T10:30:00Z",
    "verificationMethod": "did:web:shipper.example.com#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z5LbLbR3qZ5Y6m8n9o0p1q2r3s4t5u6v7w8x9y0za1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
  }
}
```

**Required Proof Fields:**

| Field | Required | Description |
|---|---|---|
| `type` | MUST | Recognized Data Integrity Proof type (`Ed25519Signature2020`, `BbsBlsSignature2020`, or `DataIntegrityProof`) |
| `created` | MUST | ISO 8601 timestamp of proof creation |
| `verificationMethod` | MUST | DID URL of the key used to create the proof |
| `proofPurpose` | MUST | MUST be `assertionMethod` for attestations |
| `proofValue` | MUST | The cryptographic proof value |

**Validation Rule:** Attestations missing the `proof` section or with unrecognized proof types SHALL be rejected with status `rejected_invalid_proof`.

---

## 6. Validation Pipeline

The UORA Resolver implements a seven-phase validation pipeline. Each phase may reject the attestation with a specific status code.

### 6.1 Phase Order

| Phase | Name | Rejection Status |
|---|---|---|
| 1 | Structural Validation | `rejected_missing_field` |
| 2 | Type Validation | `rejected_invalid_type` |
| 3 | Temporal Validation | `rejected_future_timestamp` |
| 4 | Proof Validation | `rejected_invalid_proof` |
| 5 | Governance Validation | `rejected_missing_authorization`, `rejected_unauthorized_issuer`, `rejected_expired_certification`, `rejected_unauthorized_category` |
| 6 | Antecedent Chain Validation | `rejected_broken_chain`, `rejected_linear_chain_violation` |
| 7 | Conflict Resolution | `superseded` |

### 6.2 Validation Status Codes

| Status | Description |
|---|---|
| `valid` | All validation phases passed |
| `superseded` | Valid attestation but lost conflict resolution |
| `rejected_missing_field` | Required field absent from credential |
| `rejected_invalid_type` | Type declaration mismatch or invalid subtype |
| `rejected_invalid_event_type` | Event type not in valid enumeration |
| `rejected_broken_chain` | Antecedent reference cannot be resolved or chain integrity violated |
| `rejected_missing_authorization` | No authorizedBy claim present |
| `rejected_unauthorized_issuer` | Issuer lacks valid certification |
| `rejected_expired_certification` | Certification expired at attestation time |
| `rejected_unauthorized_category` | Attestation type not in certification scope |
| `rejected_future_timestamp` | validFrom timestamp is in the future (>5 second tolerance) |
| `rejected_duplicate_id` | Attestation ID already processed |
| `rejected_invalid_proof` | Proof section missing or malformed |
| `rejected_linear_chain_violation` | Transfer/Disposition doesn't reference most recent valid event |

### 6.3 Chain Integrity States

| State | Description |
|---|---|
| `intact` | Antecedent chain is complete and validated |
| `broken` | Chain integrity violation detected |
| `superseded` | Attestation lost conflict resolution |
| `invalid` | Attestation failed structural or governance validation |

---

## 7. Complete Example

### 7.1 UORATransferAttestation (Full)

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/uora/contexts/core.jsonld",
    "https://w3id.org/verifiable-supply-chain/contexts/shipping.jsonld"
  ],
  "id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
  "type": [
    "VerifiableCredential",
    "UORAAttestation",
    "UORATransferAttestation",
    "VerifiableShippingEvent"
  ],
  "issuer": {
    "id": "did:web:shipper.example.com",
    "name": "Global Logistics Co."
  },
  "validFrom": "2026-04-28T10:30:00.000Z",
  "credentialSubject": {
    "id": "did:web:maker.example.com:object:serial:SN-001",
    "eventType": "Transfer",
    "transferType": "custody",
    "fromParty": "did:web:shipper.example.com",
    "toParty": "did:web:receiver.example.com",
    "fromLocation": "https://id.gs1.org/414/9521321000010",
    "toLocation": "https://id.gs1.org/414/9521321000096",
    "antecedent": "urn:uuid:previous-origin-attestation-id",
    "authorizedBy": {
      "certificationId": "urn:uuid:shipper-cert-credential",
      "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
      "verifiedAt": "2026-04-28T10:30:00Z"
    }
  },
  "evidence": [
    {
      "id": "urn:uuid:evidence-001",
      "type": ["Evidence", "EPCISObjectEvent"],
      "name": "Custody Transfer Handover",
      "description": "Digital handover confirmation at dock door R1",
      "epcisEventID": "ni:///sha-256;abc123def456?ver=CBV2.0",
      "epcisEventType": "ObjectEvent",
      "epcisBizStep": "shipping"
    }
  ],
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-04-28T10:30:00Z",
    "verificationMethod": "did:web:shipper.example.com#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z5LbLbR3qZ5Y6m8n9o0p1q2r3s4t5u6v7w8x9y0za1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
  }
}
```

---

## 8. Conformance

### 8.1 Compliance Levels

| Level | Requirements |
|---|---|
| **UORA Data Compliant** | Produces attestations conforming to the data model in §5 |
| **UORA Protocol Compliant** | Meets Data compliance + implements UORA-Query-API (§3.3) |
| **UORA Full Compliant** | Meets Protocol compliance + implements all seven validation phases (§6) + passes all 22 conformance tests (§8.2) |

### 8.2 Conformance Test Suite

To claim any compliance level, an implementation MUST pass the relevant test vectors published at:

```
https://w3id.org/uora/conformance/v1
```

#### 8.2.1 Test Categories (22 tests total)

| Category | Count | Description |
|---|---|---|
| Valid Attestations | 4 | Well-formed attestations of each type (Origin, Transfer, Transformation, Disposition) that MUST be accepted |
| Invalid Attestations | 5 | Malformed attestations (missing fields, invalid types, future timestamps, duplicates) that MUST be rejected |
| Governance Validation | 3 | Attestations with missing, expired, or mismatched certifications |
| Conflict Resolution | 3 | Conflicting attestation pairs verifying timestamp, authority, and multi-antecedent resolution |
| Chain Integrity | 2 | Broken antecedent chains and temporal chain violations |
| Linear Chain Enforcement | 2 | Transfer attestations that violate or correctly follow linear custody rules |
| Proof Validation | 2 | Missing proof sections and invalid proof types |
| EPCIS Evidence Linking | 1 | Attestations with EPCIS ObjectEvent evidence linking |

### 8.3 Example Test Vector

```json
{
  "testId": "valid-transfer-001",
  "category": "valid-attestations",
  "description": "A complete, well-formed TransferAttestation with all required fields",
  "input": { /* valid UORATransferAttestation */ },
  "expectedResult": "accepted",
  "expectedState": {
    "eventType": "Transfer",
    "chainIntegrity": "intact"
  }
}
```

---

## 9. Relationship to Domain Profiles

Domain-specific profiles (such as the Verifiable Supply Chain CG's `VerifiableShippingEvent`) SHALL extend the appropriate UORA attestation subtype and add industry-specific claims. Profiles SHALL NOT modify or override the governance validation rules (§4.1.3), antecedent chaining mechanism (§5.1), linear custody enforcement (§5.1.4), or conflict resolution cascade (§5.1.3) defined herein.

| UORA Attestation | Example Domain Profile(s) | EPCIS Mapping |
|---|---|---|
| `UORAOriginAttestation` | `VerifiableCommissioningEvent` | `ObjectEvent` (action=ADD, bizStep=commissioning) |
| `UORATransferAttestation` | `VerifiableShippingEvent`, `VerifiableReceivingEvent` | `ObjectEvent` (action=OBSERVE, bizStep=shipping/receiving) |
| `UORATransformationAttestation` | `VerifiableManufacturingEvent`, `VerifiableAssemblyEvent` | `TransformationEvent` |
| `UORADispositionAttestation` | `VerifiableRecyclingEvent`, `VerifiableDestructionEvent` | `ObjectEvent` (action=DELETE) |

---

## 10. Security Considerations

- **Issuer Impersonation:** Mitigated by the mandatory `CertificationCredential` validation (§4.1.3). Verifiers MUST cryptographically validate both the attestation proof and the certification proof.
- **Antecedent Chain Breaks:** Attestations whose `antecedent` cannot be resolved to a valid prior state SHALL be flagged with `"chainIntegrity": "broken"` and require manual review.
- **Custody Gap Attacks:** Linear chain enforcement (§5.1.4) prevents attackers from inserting attestations that skip over legitimate events in the custody timeline.
- **Timestamp Manipulation:** The `validFrom` timestamp MUST fall within the validity window of the Issuer's `CertificationCredential`. Attestations with timestamps more than 5 seconds in the future relative to processing time SHALL be rejected.
- **Replay Attacks:** Each attestation's `id` MUST be globally unique. Verifiers SHALL reject attestations whose `id` has been previously processed (status: `rejected_duplicate_id`).
- **Proof Forgery:** All attestations MUST carry a Data Integrity Proof (§5.8). Attestations without valid proofs SHALL be rejected.

## 11. Privacy Considerations

- **Correlation Risk:** Object DIDs are long-lived identifiers. Implementations SHOULD support pairwise DIDs where appropriate to prevent cross-verifier correlation.
- **Selective Disclosure:** Attestations MAY be presented as Verifiable Presentations with selective disclosure of claims. Verifiers SHALL NOT require disclosure of claims beyond those necessary for their business rules.
- **Data Minimization:** The `evidence` array SHOULD contain only data necessary for verification. Large payloads SHOULD be referenced via URI per §5.7.3.

---

## 12. UORA JSON-LD Context

The canonical JSON-LD context for UORA Core v1.0 is published at:

```
https://w3id.org/uora/contexts/core.jsonld
```

```json
{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",

    "UORAAttestation": { "@id": "https://w3id.org/uora#UORAAttestation" },
    "UORAOriginAttestation": { "@id": "https://w3id.org/uora#UORAOriginAttestation" },
    "UORATransferAttestation": { "@id": "https://w3id.org/uora#UORATransferAttestation" },
    "UORATransformationAttestation": { "@id": "https://w3id.org/uora#UORATransformationAttestation" },
    "UORADispositionAttestation": { "@id": "https://w3id.org/uora#UORADispositionAttestation" },
    "UORACertificationCredential": { "@id": "https://w3id.org/uora#UORACertificationCredential" },

    "eventType": "uora:eventType",
    "antecedent": { "@id": "uora:antecedent", "@type": "@id" },
    "authorizedBy": "uora:authorizedBy",

    "originType": "uora:originType",
    "originLocation": { "@id": "uora:originLocation", "@type": "@id" },
    "originDate": { "@id": "uora:originDate", "@type": "xsd:dateTime" },
    "productionBatch": "uora:productionBatch",
    "inputMaterials": { "@id": "uora:inputMaterials", "@type": "@id", "@container": "@set" },

    "transferType": "uora:transferType",
    "fromParty": { "@id": "uora:fromParty", "@type": "@id" },
    "toParty": { "@id": "uora:toParty", "@type": "@id" },
    "fromLocation": { "@id": "uora:fromLocation", "@type": "@id" },
    "toLocation": { "@id": "uora:toLocation", "@type": "@id" },

    "transformationType": "uora:transformationType",
    "inputObjects": { "@id": "uora:inputObjects", "@type": "@id", "@container": "@set" },
    "outputObjects": { "@id": "uora:outputObjects", "@type": "@id", "@container": "@set" },
    "inputQuantities": "uora:inputQuantities",
    "outputQuantities": "uora:outputQuantities",
    "transformationLocation": { "@id": "uora:transformationLocation", "@type": "@id" },
    "processCertification": { "@id": "uora:processCertification", "@type": "@id" },

    "dispositionType": "uora:dispositionType",
    "dispositionLocation": { "@id": "uora:dispositionLocation", "@type": "@id" },
    "environmentalCertification": { "@id": "uora:environmentalCertification", "@type": "@id" },

    "certificationId": { "@id": "uora:certificationId", "@type": "@id" },
    "trustFramework": { "@id": "uora:trustFramework", "@type": "@id" },
    "verifiedAt": { "@id": "uora:verifiedAt", "@type": "xsd:dateTime" },
    "authorizedAttestations": "uora:authorizedAttestations",
    "authorizedCategories": "uora:authorizedCategories",
    "authorizedRegions": "uora:authorizedRegions",

    "physicalBinding": "uora:physicalBinding",
    "bindingType": "uora:bindingType",
    "bindingDevice": "uora:bindingDevice",
    "externalData": "uora:externalData",

    "epcisEventID": "uora:epcisEventID",
    "epcisEventType": "uora:epcisEventType",
    "epcisBizStep": "uora:epcisBizStep",

    "uora": "https://w3id.org/uora#",
    "xsd": "http://www.w3.org/2001/XMLSchema#"
  }
}
```

---

## 13. References

### Normative
- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [W3C Data Integrity Proofs](https://www.w3.org/TR/vc-data-integrity/)
- [RFC 2119: Key words for use in RFCs to Indicate Requirement Levels](https://www.ietf.org/rfc/rfc2119.txt)
- [RFC 8259: The JavaScript Object Notation (JSON) Data Interchange Format](https://www.ietf.org/rfc/rfc8259.txt)
- [ISO 8601: Date and time format](https://www.iso.org/iso-8601-date-and-time-format.html)

### Informative
- [GS1 EPCIS 2.0 Standard](https://www.gs1.org/standards/epcis)
- [Verifiable Supply Chain Community Group Charter](https://www.w3.org/community/verifiable-supply-chain/)
- [UORA Community Group Charter](https://www.w3.org/community/uora/)
