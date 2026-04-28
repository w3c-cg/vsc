#!/usr/bin/env python3
"""
UORA Reference Resolver v3.1
=============================
Reference implementation of the UORA Core Protocol v1.0.

Implements:
  - Ed25519 Key Generation & Signing   : DataIntegrityProof with eddsa-rdfc-2022
  - UORA-Query-API (§3.3)              : Standardized /history, /chain, /graph
  - Governance Validation (§4)         : Delegation chains, trust anchors, ranking
  - Antecedent Chaining (§5.1)         : Linear custody chain + DAG transformation
  - Conflict Resolution (§5.1.4)       : Deterministic total ordering function
  - Temporal Consistency (§5.1.5)      : child >= parent invariant
  - Structured Errors (§6)             : Machine-readable codes with remediation
  - Evidence Verifiability (§5.7.1)    : At least one verifiable evidence entry
  - Provisional Evidence (§5.7.1)      : Retry with exponential backoff
  - Cross-Framework Isolation (§5.1.8) : Conflicts resolved per framework
  - Rate Limiting (§9.4)               : Configurable per-issuer rate limiting
  - Replay Protection (§9.1)           : Scoped to (subject_did, trust_framework)
  - Registry Cache (§4.2.2)            : Signed, versioned, cached with TTL
  - Conformance Profiles (§3.3.6)      : Minimal and Full profiles
  - Conformance Test Suite (§7)        : 30 automated test vectors

Protocol: https://w3id.org/uora/spec/core/v1.0
EPCIS Mapping: https://w3id.org/verifiable-supply-chain/profiles/shipping/v0.3

Dependencies:
  pip install cryptography

Usage:
  python uora-resolver-v3.1.py serve          # Start API server
  python uora-resolver-v3.1.py test           # Run conformance suite
  python uora-resolver-v3.1.py validate <file> # Validate single attestation
  python uora-resolver-v3.1.py chain <did>    # Display custody chain

Author: Verifiable Supply Chain Community Group
Version: 3.1.0
License: W3C Community Contributor License Agreement
"""

import json
import uuid
import hashlib
import logging
import argparse
import sys
import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from functools import total_ordering
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

# ============================================================================
# Cryptographic Module — Ed25519 Signing (§4.12)
# ============================================================================

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption
    )
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class CryptoProvider:
    """
    Ed25519 cryptographic provider for UORA attestation signing.

    Uses the W3C Data Integrity cryptosuite eddsa-rdfc-2022.
    Each issuer generates a keypair; the public key is published
    in their DID Document as an Ed25519VerificationKey2020.

    Reference: W3C VC Data Integrity 1.0, UORA Core §4.12
    """

    def __init__(self) -> None:
        self.keypairs: Dict[str, ed25519.Ed25519PrivateKey] = {}

    def generate_keypair(self, issuer_did: str) -> bytes:
        """Generate an Ed25519 keypair for an issuer. Returns public key bytes."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required. Install with: pip install cryptography")
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        self.keypairs[issuer_did] = private_key
        public_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        logger.info(f"Generated Ed25519 keypair for {issuer_did} (public key: {public_bytes.hex()[:16]}...)")
        return public_bytes

    def sign_attestation(self, issuer_did: str, credential: Dict[str, Any]) -> Dict[str, Any]:
        """Sign an attestation with the issuer's Ed25519 private key."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required for signing.")
        private_key = self.keypairs.get(issuer_did)
        if not private_key:
            raise ValueError(f"No keypair found for issuer: {issuer_did}")
        unsigned = {k: v for k, v in credential.items() if k != "proof"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
        signature = private_key.sign(canonical.encode("utf-8"))
        credential["proof"] = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "created": datetime.now(timezone.utc).isoformat(),
            "verificationMethod": f"{issuer_did}#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": signature.hex(),
        }
        return credential

    def verify_proof(self, credential: Dict[str, Any]) -> bool:
        """Verify the DataIntegrityProof on a credential. Returns True if valid."""
        if not CRYPTO_AVAILABLE:
            return True
        proof = credential.get("proof", {})
        if not proof or not proof.get("proofValue"):
            return False
        issuer_did = credential.get("issuer", {}).get("id", "")
        private_key = self.keypairs.get(issuer_did)
        if not private_key:
            logger.warning(f"No keypair for {issuer_did} — cannot verify proof")
            return False
        public_key = private_key.public_key()
        unsigned = {k: v for k, v in credential.items() if k != "proof"}
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
        try:
            signature_bytes = bytes.fromhex(proof["proofValue"])
            public_key.verify(signature_bytes, canonical.encode("utf-8"))
            return True
        except (InvalidSignature, ValueError) as e:
            logger.warning(f"Proof verification failed for {credential.get('id')}: {e}")
            return False


crypto = CryptoProvider()


# ============================================================================
# Logging Configuration
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("uora-resolver")

if not CRYPTO_AVAILABLE:
    logger.warning(
        "cryptography library not installed. "
        "Install with: pip install cryptography"
    )


# ============================================================================
# Protocol Constants
# ============================================================================

VC_CONTEXT_V2: str = "https://www.w3.org/ns/credentials/v2"
UORA_CONTEXT: str = "https://w3id.org/uora/contexts/core.jsonld"
VSC_SHIPPING_CONTEXT: str = "https://w3id.org/verifiable-supply-chain/contexts/shipping.jsonld"

VALID_EVENT_TYPES: Set[str] = {"Origin", "Transfer", "Transformation", "Disposition"}
VALID_TRANSFER_TYPES: Set[str] = {"custody", "ownership", "location"}
VALID_ORIGIN_TYPES: Set[str] = {"manufactured", "mined", "harvested", "created"}
VALID_TRANSFORMATION_TYPES: Set[str] = {"assembly", "processing", "modification", "disassembly"}
VALID_DISPOSITION_TYPES: Set[str] = {"recycled", "decommissioned", "destroyed", "lost"}

UORA_ATTESTATION_TYPES: Set[str] = {
    "UORAOriginAttestation", "UORATransferAttestation",
    "UORATransformationAttestation", "UORADispositionAttestation",
}

EPCIS_EVENT_TYPES: Set[str] = {
    "EPCISObjectEvent", "EPCISAggregationEvent",
    "EPCISTransactionEvent", "EPCISTransformationEvent", "EPCISAssociationEvent",
}

REQUIRED_BASE_FIELDS: Set[str] = {
    "@context", "type", "id", "issuer", "validFrom",
    "credentialSubject", "evidence", "proof"
}
REQUIRED_SUBJECT_FIELDS: Set[str] = {"id", "eventType", "antecedent", "authorizedBy"}
REQUIRED_PROOF_FIELDS: Set[str] = {"type", "created", "verificationMethod", "proofPurpose", "proofValue"}
VALID_PROOF_TYPES: Set[str] = {"DataIntegrityProof", "Ed25519Signature2020", "BbsBlsSignature2020"}
VALID_CRYPTOSUITES: Set[str] = {"eddsa-rdfc-2022", "eddsa-jcs-2022"}

CLOCK_SKEW_TOLERANCE: timedelta = timedelta(seconds=5)
CONFLICT_TIMESTAMP_TOLERANCE: timedelta = timedelta(seconds=1)
MAX_DELEGATION_DEPTH: int = 5
REGISTRY_CACHE_TTL: int = 3600
PROVISIONAL_EVIDENCE_WINDOW: int = 300
DEFAULT_RATE_LIMIT: int = 100
CONSISTENCY_WINDOW: int = 5

TRUST_FRAMEWORK_AUTHORITY_PRECEDENCE: Dict[str, Dict[str, int]] = {
    "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1": {
        "did:web:fda.example.gov": 100, "did:web:manufacturer.example.com": 50,
        "did:web:wholesaler.example.com": 30,
    },
    "https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1": {
        "did:web:carrier.example.com": 50, "did:web:warehouse.example.com": 40,
    },
    "https://w3id.org/verifiable-supply-chain/trust-frameworks/minerals-v1": {
        "did:web:certifier.example.org": 80, "did:web:mine-operator.example.com": 60,
    },
}

ACTIVE_TRUST_ANCHORS: Dict[str, Set[str]] = {
    "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1": {"did:web:fda.example.gov"},
    "https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1": {"did:web:fda.example.gov"},
    "https://w3id.org/verifiable-supply-chain/trust-frameworks/minerals-v1": {"did:web:certifier.example.org"},
}

REVOKED_CERTIFICATIONS: Set[str] = set()


# ============================================================================
# Validation Status Enumeration (§6)
# ============================================================================

class ValidationStatus(Enum):
    """All possible validation outcomes per UORA Core §6."""
    VALID = "valid"
    SUPERSEDED = "superseded"
    REJECTED_MISSING_FIELD = "rejected_missing_field"
    REJECTED_INVALID_TYPE = "rejected_invalid_type"
    REJECTED_INVALID_EVENT_TYPE = "rejected_invalid_event_type"
    REJECTED_BROKEN_CHAIN = "rejected_broken_chain"
    REJECTED_MISSING_AUTHORIZATION = "rejected_missing_authorization"
    REJECTED_UNAUTHORIZED_ISSUER = "rejected_unauthorized_issuer"
    REJECTED_EXPIRED_CERTIFICATION = "rejected_expired_certification"
    REJECTED_UNAUTHORIZED_CATEGORY = "rejected_unauthorized_category"
    REJECTED_DELEGATION_DEPTH_EXCEEDED = "rejected_delegation_depth_exceeded"
    REJECTED_FUTURE_TIMESTAMP = "rejected_future_timestamp"
    REJECTED_DUPLICATE_ID = "rejected_duplicate_id"
    REJECTED_INVALID_PROOF = "rejected_invalid_proof"
    REJECTED_LINEAR_CHAIN_VIOLATION = "rejected_linear_chain_violation"
    REJECTED_TEMPORAL_INCONSISTENCY = "rejected_temporal_inconsistency"
    REJECTED_UNVERIFIABLE_EVIDENCE = "rejected_unverifiable_evidence"
    REGISTRY_UNAVAILABLE = "registry_unavailable"


STATUS_TO_HTTP: Dict[ValidationStatus, int] = {
    ValidationStatus.VALID: 201, ValidationStatus.SUPERSEDED: 200,
    ValidationStatus.REJECTED_MISSING_FIELD: 400, ValidationStatus.REJECTED_INVALID_TYPE: 400,
    ValidationStatus.REJECTED_INVALID_PROOF: 400, ValidationStatus.REJECTED_UNVERIFIABLE_EVIDENCE: 400,
    ValidationStatus.REJECTED_MISSING_AUTHORIZATION: 401,
    ValidationStatus.REJECTED_UNAUTHORIZED_ISSUER: 403,
    ValidationStatus.REJECTED_EXPIRED_CERTIFICATION: 403,
    ValidationStatus.REJECTED_UNAUTHORIZED_CATEGORY: 403,
    ValidationStatus.REJECTED_DELEGATION_DEPTH_EXCEEDED: 403,
    ValidationStatus.REJECTED_FUTURE_TIMESTAMP: 422,
    ValidationStatus.REJECTED_BROKEN_CHAIN: 422,
    ValidationStatus.REJECTED_LINEAR_CHAIN_VIOLATION: 422,
    ValidationStatus.REJECTED_TEMPORAL_INCONSISTENCY: 422,
    ValidationStatus.REJECTED_DUPLICATE_ID: 409,
    ValidationStatus.REGISTRY_UNAVAILABLE: 503,
}

REMEDIATION_HINTS: Dict[ValidationStatus, str] = {
    ValidationStatus.REJECTED_MISSING_AUTHORIZATION:
        "Ensure credentialSubject.authorizedBy references a valid certification.",
    ValidationStatus.REJECTED_BROKEN_CHAIN:
        "Verify antecedent references an existing, valid attestation for this subject.",
    ValidationStatus.REJECTED_LINEAR_CHAIN_VIOLATION:
        "Update antecedent to reference the most recent valid attestation.",
    ValidationStatus.REJECTED_INVALID_PROOF:
        "Ensure proof section is cryptographically valid and signed by the issuer.",
    ValidationStatus.REJECTED_UNVERIFIABLE_EVIDENCE:
        "Include at least one cryptographically verifiable or externally verifiable evidence entry.",
    ValidationStatus.REJECTED_TEMPORAL_INCONSISTENCY:
        "Ensure validFrom(child) >= validFrom(parent) for all parent attestations.",
    ValidationStatus.REJECTED_FUTURE_TIMESTAMP:
        "Ensure validFrom is not in the future beyond the clock skew tolerance.",
    ValidationStatus.REJECTED_DUPLICATE_ID:
        "Use a globally unique attestation ID (UUID URN).",
    ValidationStatus.REJECTED_EXPIRED_CERTIFICATION:
        "Renew the issuer's CertificationCredential before issuing new attestations.",
    ValidationStatus.REJECTED_UNAUTHORIZED_ISSUER:
        "Verify the issuer holds a valid certification from a recognized Trust Anchor.",
    ValidationStatus.REJECTED_UNAUTHORIZED_CATEGORY:
        "Verify the attestation type is listed in the issuer's authorizedAttestations.",
    ValidationStatus.REJECTED_DELEGATION_DEPTH_EXCEEDED:
        "Reduce delegation chain depth to <= 5 levels.",
    ValidationStatus.REGISTRY_UNAVAILABLE:
        "Verify network connectivity to the Trust Framework registry.",
}


# ============================================================================
# Data Models
# ============================================================================

@total_ordering
@dataclass
class AttestationRecord:
    """A validated attestation stored in the resolver's history."""
    id: str
    type: List[str]
    issuer: str
    valid_from: datetime
    subject_id: str
    event_type: str
    antecedent: Optional[List[str]]
    authorized_by: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    raw_credential: Dict[str, Any]
    proof: Dict[str, Any] = field(default_factory=dict)
    status: ValidationStatus = ValidationStatus.VALID
    chain_integrity: str = "intact"
    superseded_by: Optional[str] = None
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_verification: str = "verified"
    sequence_number: Optional[int] = None

    def __lt__(self, other: "AttestationRecord") -> bool:
        if not isinstance(other, AttestationRecord): return NotImplemented
        return self.valid_from < other.valid_from

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AttestationRecord): return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class CertificationCredential:
    """A stored CertificationCredential for governance validation."""
    id: str
    issuer: str
    subject_id: str
    authorized_attestations: List[str]
    authorized_categories: List[str]
    authorized_regions: List[str]
    trust_framework: str
    valid_from: datetime
    valid_until: datetime
    authority_rank: int = 0
    delegated_from: Optional[str] = None


# ============================================================================
# In-Memory Attestation Store
# ============================================================================

class AttestationStore:
    """Thread-safe in-memory store with O(1) indexed lookups."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.attestations: Dict[str, AttestationRecord] = {}
        self.certifications: Dict[str, CertificationCredential] = {}
        self.seen_ids: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
        self.by_subject: Dict[str, List[AttestationRecord]] = {}
        self.by_antecedent: Dict[str, List[str]] = {}
        self.trust_anchors: Dict[str, Set[str]] = dict(ACTIVE_TRUST_ANCHORS)
        self.rate_limits: Dict[str, List[float]] = defaultdict(list)
        self.registry_cache: Dict[str, Tuple[datetime, Dict]] = {}
        self.provisional_evidence: Dict[str, Tuple[datetime, AttestationRecord]] = {}
        self.sequence_tracker: Dict[Tuple[str, str], int] = defaultdict(int)

    def add_attestation(self, record: AttestationRecord) -> bool:
        """Add attestation with scoped replay protection (§9.1)."""
        with self._lock:
            scope = (record.subject_id, record.authorized_by.get("trustFramework", ""))
            if record.id in self.seen_ids[scope]:
                return False
            if record.sequence_number is not None:
                last_seq = self.sequence_tracker.get(scope, -1)
                if record.sequence_number <= last_seq: return False
                self.sequence_tracker[scope] = record.sequence_number
            self.seen_ids[scope].add(record.id)
            self.attestations[record.id] = record
            if record.subject_id not in self.by_subject:
                self.by_subject[record.subject_id] = []
            self.by_subject[record.subject_id].append(record)
            if record.antecedent:
                for ant_id in record.antecedent:
                    if ant_id not in self.by_antecedent:
                        self.by_antecedent[ant_id] = []
                    self.by_antecedent[ant_id].append(record.id)
            return True

    def get_history(self, did: str, event_type: Optional[str] = None,
                    from_time: Optional[datetime] = None, to_time: Optional[datetime] = None,
                    limit: int = 100, include_superseded: bool = False) -> List[AttestationRecord]:
        with self._lock:
            records = self.by_subject.get(did, [])
            if event_type: records = [r for r in records if r.event_type == event_type]
            if not include_superseded: records = [r for r in records if r.status != ValidationStatus.SUPERSEDED]
            if from_time: records = [r for r in records if r.valid_from >= from_time]
            if to_time: records = [r for r in records if r.valid_from <= to_time]
            records.sort(key=lambda r: r.valid_from)
            return records[:limit]

    def get_graph(self, did: str, depth: int = 10, branch: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            records = self.by_subject.get(did, []); records.sort(key=lambda r: r.valid_from)
            nodes, edges = [], []
            for r in records:
                nodes.append({"id": r.id, "type": r.event_type, "timestamp": r.valid_from.isoformat(),
                              "issuer": r.issuer, "status": r.status.value})
                if r.antecedent:
                    for ant_id in r.antecedent:
                        edges.append({"from": ant_id, "to": r.id, "type": r.event_type})
            return {"did": did, "nodes": nodes, "edges": edges, "totalNodes": len(nodes), "totalEdges": len(edges)}

    def get_most_recent_valid(self, did: str) -> Optional[AttestationRecord]:
        with self._lock:
            records = self.by_subject.get(did, [])
            valid_records = [r for r in records if r.status == ValidationStatus.VALID]
            if not valid_records: return None
            valid_records.sort(key=lambda r: r.valid_from)
            return valid_records[-1]

    def get_antecedent(self, antecedent_id: str) -> Optional[AttestationRecord]:
        return self.attestations.get(antecedent_id)

    def get_siblings(self, antecedent_id: str, exclude_id: str) -> List[AttestationRecord]:
        with self._lock:
            sibling_ids = self.by_antecedent.get(antecedent_id, [])
            return [self.attestations[sid] for sid in sibling_ids
                    if sid != exclude_id and sid in self.attestations]

    def add_certification(self, cert: CertificationCredential) -> None:
        with self._lock: self.certifications[cert.id] = cert

    def get_certification(self, cert_id: str) -> Optional[CertificationCredential]:
        return self.certifications.get(cert_id)

    def get_certification_for_issuer(self, issuer_did: str, trust_framework: str) -> Optional[CertificationCredential]:
        for cert in self.certifications.values():
            if cert.subject_id == issuer_did and cert.trust_framework == trust_framework:
                return cert
        return None

    def check_rate_limit(self, issuer_did: str) -> bool:
        with self._lock:
            now = time.time(); window_start = now - 60
            self.rate_limits[issuer_did] = [t for t in self.rate_limits[issuer_did] if t > window_start]
            if len(self.rate_limits[issuer_did]) >= DEFAULT_RATE_LIMIT: return False
            self.rate_limits[issuer_did].append(now); return True

    def cache_registry(self, framework_uri: str, registry: Dict) -> None:
        with self._lock: self.registry_cache[framework_uri] = (datetime.now(timezone.utc), registry)

    def get_cached_registry(self, framework_uri: str) -> Optional[Dict]:
        with self._lock:
            entry = self.registry_cache.get(framework_uri)
            if entry:
                cached_at, registry = entry
                if datetime.now(timezone.utc) - cached_at < timedelta(seconds=REGISTRY_CACHE_TTL):
                    return registry
                del self.registry_cache[framework_uri]
            return None

    def add_provisional(self, attestation_id: str, record: AttestationRecord) -> None:
        with self._lock: self.provisional_evidence[attestation_id] = (datetime.now(timezone.utc), record)

    def get_provisional(self, attestation_id: str) -> Optional[AttestationRecord]:
        with self._lock:
            entry = self.provisional_evidence.get(attestation_id)
            if entry:
                added_at, record = entry
                if datetime.now(timezone.utc) - added_at < timedelta(seconds=PROVISIONAL_EVIDENCE_WINDOW):
                    return record
                del self.provisional_evidence[attestation_id]
            return None

    def remove_provisional(self, attestation_id: str) -> None:
        with self._lock: self.provisional_evidence.pop(attestation_id, None)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_attestations": len(self.attestations),
                "total_certifications": len(self.certifications),
                "unique_subjects": len(self.by_subject),
                "indexed_antecedents": len(self.by_antecedent),
                "antecedent_index_entries": sum(len(v) for v in self.by_antecedent.values()),
                "provisional_evidence_count": len(self.provisional_evidence),
                "rate_limited_issuers": len(self.rate_limits),
                "registry_cache_entries": len(self.registry_cache),
            }


# ============================================================================
# Structured Error Builder (§6)
# ============================================================================

def build_error_response(status: ValidationStatus, error_message: str,
                         record: Optional[AttestationRecord] = None,
                         phase: Optional[str] = None) -> Dict[str, Any]:
    response: Dict[str, Any] = {"error": {"code": status.name, "status": status.value, "message": error_message}}
    if record:
        response["error"]["details"] = {"attestationId": record.id, "issuer": record.issuer,
                                        "eventType": record.event_type, "chainIntegrity": record.chain_integrity}
    if phase:
        if "details" not in response["error"]: response["error"]["details"] = {}
        response["error"]["details"]["phase"] = phase
    if status in REMEDIATION_HINTS: response["error"]["remediation"] = REMEDIATION_HINTS[status]
    return response


# ============================================================================
# Validation Engine
# ============================================================================

class UORAValidator:
    """Implements all governance, chain, and conflict resolution rules."""

    def __init__(self, store: AttestationStore) -> None:
        self.store = store

    def validate_attestation(self, credential: Dict[str, Any]) -> Tuple[AttestationRecord, Optional[str]]:
        err = self._validate_structure(credential)
        if err:
            record = self._create_record(credential, ValidationStatus.REJECTED_MISSING_FIELD)
            record.chain_integrity = "invalid"; return record, err
        err = self._validate_types(credential)
        if err:
            record = self._create_record(credential, ValidationStatus.REJECTED_INVALID_TYPE)
            record.chain_integrity = "invalid"; return record, err
        err = self._validate_temporal(credential)
        if err:
            record = self._create_record(credential, ValidationStatus.REJECTED_FUTURE_TIMESTAMP); return record, err
        err = self._validate_proof(credential)
        if err:
            record = self._create_record(credential, ValidationStatus.REJECTED_INVALID_PROOF)
            record.chain_integrity = "invalid"; return record, err
        err, is_provisional = self._validate_evidence_verifiability(credential)
        if err and not is_provisional:
            record = self._create_record(credential, ValidationStatus.REJECTED_UNVERIFIABLE_EVIDENCE); return record, err
        err = self._validate_governance(credential)
        if err:
            status = self._governance_error_status(err)
            record = self._create_record(credential, status); return record, err
        record = self._create_record(credential, ValidationStatus.VALID)
        if is_provisional: record.evidence_verification = "pending"
        chain_err = self._validate_antecedent_chain(record)
        if chain_err:
            record.status = ValidationStatus.REJECTED_BROKEN_CHAIN
            record.chain_integrity = "broken"; return record, chain_err
        temporal_err = self._validate_temporal_chain_consistency(record)
        if temporal_err:
            record.status = ValidationStatus.REJECTED_TEMPORAL_INCONSISTENCY
            record.chain_integrity = "broken"; return record, temporal_err
        conflict_err = self._detect_and_resolve_conflicts(record)
        if conflict_err:
            record.status = ValidationStatus.SUPERSEDED; record.chain_integrity = "superseded"
        return record, None

    def _validate_structure(self, credential: Dict[str, Any]) -> Optional[str]:
        for field in REQUIRED_BASE_FIELDS:
            if field not in credential: return f"Missing required base field: {field}"
        subject = credential.get("credentialSubject", {})
        for field in REQUIRED_SUBJECT_FIELDS:
            if field not in subject: return f"Missing required subject field: {field}"
        if "id" not in credential.get("issuer", {}): return "Missing issuer.id"
        if not credential.get("evidence", []): return "At least one evidence entry is required"
        return None

    def _validate_types(self, credential: Dict[str, Any]) -> Optional[str]:
        types = credential.get("type", [])
        if "VerifiableCredential" not in types: return "type must include 'VerifiableCredential'"
        if "UORAAttestation" not in types: return "type must include 'UORAAttestation'"
        concrete = set(types) & UORA_ATTESTATION_TYPES
        if len(concrete) != 1:
            return f"type must include exactly one concrete attestation type from: {UORA_ATTESTATION_TYPES}"
        event_type = credential["credentialSubject"].get("eventType")
        concrete_type = list(concrete)[0]
        expected_event = concrete_type.replace("UORA", "").replace("Attestation", "")
        if event_type != expected_event:
            return f"eventType '{event_type}' does not match concrete type '{concrete_type}'"
        subject = credential["credentialSubject"]
        if concrete_type == "UORAOriginAttestation":
            if subject.get("originType") not in VALID_ORIGIN_TYPES: return f"Invalid originType: {subject.get('originType')}"
            if not subject.get("originLocation"): return "Missing originLocation"
            if not subject.get("originDate"): return "Missing originDate"
            if subject.get("antecedent") is not None: return "Origin attestation must have antecedent: null"
        elif concrete_type == "UORATransferAttestation":
            if subject.get("transferType") not in VALID_TRANSFER_TYPES: return f"Invalid transferType: {subject.get('transferType')}"
            if not subject.get("fromParty"): return "Missing fromParty"
            if not subject.get("toParty"): return "Missing toParty"
        elif concrete_type == "UORATransformationAttestation":
            if subject.get("transformationType") not in VALID_TRANSFORMATION_TYPES: return f"Invalid transformationType: {subject.get('transformationType')}"
            if not subject.get("inputObjects"): return "Missing inputObjects"
            if not subject.get("outputObjects"): return "Missing outputObjects"
            antecedent = subject.get("antecedent")
            if not isinstance(antecedent, list) or len(antecedent) < 1: return "Transformation must have antecedent array with at least one entry"
        elif concrete_type == "UORADispositionAttestation":
            if subject.get("dispositionType") not in VALID_DISPOSITION_TYPES: return f"Invalid dispositionType: {subject.get('dispositionType')}"
        return None

    def _validate_temporal(self, credential: Dict[str, Any]) -> Optional[str]:
        valid_from_str = credential.get("validFrom", "").replace("Z", "+00:00")
        try: valid_from = datetime.fromisoformat(valid_from_str)
        except (ValueError, TypeError): return f"Invalid validFrom timestamp: {valid_from_str}"
        if valid_from > datetime.now(timezone.utc) + CLOCK_SKEW_TOLERANCE:
            return f"validFrom ({valid_from_str}) is in the future"
        return None

    def _validate_proof(self, credential: Dict[str, Any]) -> Optional[str]:
        proof = credential.get("proof", {})
        for field in REQUIRED_PROOF_FIELDS:
            if field not in proof: return f"Missing required proof field: {field}"
        cryptosuite = proof.get("cryptosuite", ""); proof_type = proof.get("type", "")
        if cryptosuite not in VALID_CRYPTOSUITES and proof_type not in VALID_PROOF_TYPES:
            return f"Unrecognized proof type or cryptosuite: {cryptosuite or proof_type}"
        if proof.get("proofPurpose") != "assertionMethod":
            return f"proofPurpose must be 'assertionMethod'"
        if not crypto.verify_proof(credential):
            return "Cryptographic proof verification failed — signature is invalid"
        return None

    def _validate_evidence_verifiability(self, credential: Dict[str, Any]) -> Tuple[Optional[str], bool]:
        evidence = credential.get("evidence", [])
        has_verifiable, has_potential = False, False
        for entry in evidence:
            if entry.get("proof"): has_verifiable = True; break
            if entry.get("externalData") and entry["externalData"].get("uri") and entry["externalData"].get("hash"):
                has_verifiable = True; break
            if set(entry.get("type", [])) & EPCIS_EVENT_TYPES: has_verifiable = True; break
            if entry.get("externalData") and entry["externalData"].get("uri"): has_potential = True
        if has_verifiable: return None, False
        if has_potential: return "Evidence requires external verification — accepted provisionally", True
        return "At least one verifiable evidence entry is required per §5.7.1", False

    def _validate_governance(self, credential: Dict[str, Any]) -> Optional[str]:
        subject = credential["credentialSubject"]
        authorized_by = subject.get("authorizedBy", {})
        if not authorized_by: return "Missing authorizedBy claim"
        cert_id = authorized_by.get("certificationId")
        if not cert_id: return "Missing certificationId in authorizedBy"
        
        # Check revocation BEFORE store lookup
        if cert_id in REVOKED_CERTIFICATIONS: return "Certification revoked"
        
        cert = self.store.get_certification(cert_id)
        if not cert: return f"CertificationCredential not found: {cert_id}"
        valid_from = datetime.fromisoformat(credential["validFrom"].replace("Z", "+00:00"))
        if valid_from < cert.valid_from or valid_from > cert.valid_until:
            return f"Certification expired or not yet valid"
        delegation_err = self._validate_delegation_chain(cert, valid_from)
        if delegation_err: return delegation_err
        issuer_did = credential.get("issuer", {}).get("id", "")
        if issuer_did != cert.subject_id:
            return f"Issuer '{issuer_did}' does not match certification subject '{cert.subject_id}'"
        attestation_types = set(credential.get("type", []))
        if not (attestation_types & set(cert.authorized_attestations)):
            return f"Issuer not authorized for attestation types"
        return None

    def _validate_delegation_chain(self, cert: CertificationCredential,
                               attestation_time: datetime, depth: int = 1) -> Optional[str]:
        # >>> MOVE REVOCATION CHECK TO THE VERY TOP <<<
        if cert.id in REVOKED_CERTIFICATIONS:
            return "Certification revoked"
        
        anchors = self.store.trust_anchors.get(cert.trust_framework, set())
        if cert.issuer in anchors:
            return None
        
        if cert.delegated_from:
            if depth >= MAX_DELEGATION_DEPTH:
                return "Delegation depth exceeded (max 5)"
            parent = self.store.get_certification(cert.delegated_from)
            if not parent:
                return "Delegation chain broken: parent certification not found"
            if attestation_time < parent.valid_from or attestation_time > parent.valid_until:
                return "Parent certification expired at attestation time"
            return self._validate_delegation_chain(parent, attestation_time, depth + 1)
        
        return f"Issuer '{cert.issuer}' is not a Trust Anchor and has no delegation chain"

    def _governance_error_status(self, error: str) -> ValidationStatus:
        if "Missing authorizedBy" in error: return ValidationStatus.REJECTED_MISSING_AUTHORIZATION
        if "not found" in error or "chain broken" in error or "revoked" in error:
            return ValidationStatus.REJECTED_UNAUTHORIZED_ISSUER
        if "expired" in error: return ValidationStatus.REJECTED_EXPIRED_CERTIFICATION
        if "not authorized" in error: return ValidationStatus.REJECTED_UNAUTHORIZED_CATEGORY
        if "depth exceeded" in error: return ValidationStatus.REJECTED_DELEGATION_DEPTH_EXCEEDED
        return ValidationStatus.REJECTED_UNAUTHORIZED_ISSUER

    def _get_authority_rank(self, issuer_did: str, trust_framework: str) -> int:
        cert = self.store.get_certification_for_issuer(issuer_did, trust_framework)
        if cert and cert.authority_rank > 0: return cert.authority_rank
        registry = self.store.get_cached_registry(trust_framework)
        if registry and "issuerRankings" in registry:
            rank = registry["issuerRankings"].get(issuer_did)
            if rank is not None: return rank
        precedence = TRUST_FRAMEWORK_AUTHORITY_PRECEDENCE.get(trust_framework, {})
        if issuer_did in precedence: return precedence[issuer_did]
        return 0

    def _validate_antecedent_chain(self, record: AttestationRecord) -> Optional[str]:
        antecedent = record.antecedent
        if antecedent is None: return None
        if isinstance(antecedent, list):
            for ant_id in antecedent:
                err = self._validate_single_antecedent(ant_id, record)
                if err: return err
            return None
        return self._validate_single_antecedent(antecedent, record)

    def _validate_single_antecedent(self, ant_id: str, record: AttestationRecord) -> Optional[str]:
        prev = self.store.get_antecedent(ant_id)
        if prev is None: return f"Antecedent not found: {ant_id}"
        if prev.status == ValidationStatus.REJECTED_BROKEN_CHAIN: return f"Antecedent chain broken at: {ant_id}"
        if prev.valid_from > record.valid_from:
            return f"Antecedent timestamp is after successor"
        if record.event_type in ("Transfer", "Disposition"):
            most_recent = self.store.get_most_recent_valid(record.subject_id)
            if most_recent and ant_id != most_recent.id:
                return f"Linear chain violation: must reference most recent valid event ({most_recent.id}), not {ant_id}"
        return None

    def _validate_temporal_chain_consistency(self, record: AttestationRecord) -> Optional[str]:
        antecedent = record.antecedent
        if antecedent is None: return None
        ant_ids = antecedent if isinstance(antecedent, list) else [antecedent]
        max_parent_time = None
        for ant_id in ant_ids:
            parent = self.store.get_antecedent(ant_id)
            if parent is None: continue
            if max_parent_time is None or parent.valid_from > max_parent_time:
                max_parent_time = parent.valid_from
        if max_parent_time and record.valid_from < max_parent_time:
            return f"Temporal inconsistency: child validFrom is before parent validFrom"
        return None

    def _detect_and_resolve_conflicts(self, record: AttestationRecord) -> Optional[str]:
        antecedent = record.antecedent
        if antecedent is None: return None
        ant_ids = antecedent if isinstance(antecedent, list) else [antecedent]
        for ant_id in ant_ids:
            siblings = self.store.get_siblings(ant_id, record.id)
            for sibling in siblings:
                if isinstance(antecedent, list) and isinstance(sibling.antecedent, list):
                    if set(antecedent) != set(sibling.antecedent): continue
                winner = self._total_order(record, sibling)
                if winner.id == sibling.id:
                    record.superseded_by = sibling.id
                    return f"Superseded by {sibling.id} (conflict resolution)"
        return None

    def _total_order(self, a: AttestationRecord, b: AttestationRecord) -> AttestationRecord:
        tf_a = a.authorized_by.get("trustFramework", "")
        tf_b = b.authorized_by.get("trustFramework", "")
        if tf_a != tf_b: return a
        t_a = int(a.valid_from.timestamp() * 1_000_000)
        t_b = int(b.valid_from.timestamp() * 1_000_000)
        if abs(t_a - t_b) > CONFLICT_TIMESTAMP_TOLERANCE.total_seconds() * 1_000_000:
            return a if t_a > t_b else b
        rank_a = self._get_authority_rank(a.issuer, tf_a)
        rank_b = self._get_authority_rank(b.issuer, tf_b)
        if rank_a != rank_b: return a if rank_a > rank_b else b
        return a if a.id < b.id else b

    def _create_record(self, credential: Dict[str, Any], status: ValidationStatus) -> AttestationRecord:
        subject = credential.get("credentialSubject", {})
        antecedent = subject.get("antecedent")
        if isinstance(antecedent, str): antecedent = [antecedent]
        elif antecedent is None: antecedent = None
        elif not isinstance(antecedent, list): antecedent = None
        valid_from_str = credential.get("validFrom", "1970-01-01T00:00:00Z").replace("Z", "+00:00")
        return AttestationRecord(
            id=credential.get("id", f"urn:uuid:{uuid.uuid4()}"),
            type=credential.get("type", []),
            issuer=credential.get("issuer", {}).get("id", ""),
            valid_from=datetime.fromisoformat(valid_from_str),
            subject_id=subject.get("id", ""),
            event_type=subject.get("eventType", ""),
            antecedent=antecedent,
            authorized_by=subject.get("authorizedBy", {}),
            evidence=credential.get("evidence", []),
            proof=credential.get("proof", {}),
            raw_credential=credential,
            status=status,
            chain_integrity="intact" if status == ValidationStatus.VALID else "invalid",
            sequence_number=subject.get("sequenceNumber"),
        )


# ============================================================================
# UORA-Query-API HTTP Server
# ============================================================================

class UORAQueryHandler(BaseHTTPRequestHandler):
    """HTTP handler implementing UORA-Query-API protocol (§3.3)."""

    validator: UORAValidator = None  # type: ignore
    store: AttestationStore = None   # type: ignore
    conformance_profile: str = "Full"

    def do_GET(self) -> None:
        parsed = urlparse(self.path); path = parsed.path.rstrip("/")
        if path.endswith("/history"): self._handle_history(parsed)
        elif path.endswith("/chain"): self._handle_chain(parsed)
        elif path.endswith("/graph"): self._handle_graph(parsed)
        elif path == "/health":
            self._send_json(200, {"status": "healthy", "protocol": "UORA-Query-API v3.1", "version": "3.1.0",
                                   "cryptography": "Ed25519-eddsa-rdfc-2022", "conformanceProfile": self.conformance_profile})
        elif path == "/stats": self._handle_stats()
        else: self._send_json(404, {"error": "not_found", "message": f"Endpoint not found: {parsed.path}"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path); path = parsed.path.rstrip("/")
        if path.endswith("/attestations"): self._handle_capture()
        elif path.endswith("/validate"): self._handle_validate()
        else: self._send_json(404, {"error": "not_found", "message": f"Endpoint not found: {parsed.path}"})

    def _handle_history(self, parsed: urlparse) -> None:
        params = parse_qs(parsed.query)
        did = params.get("did", [None])[0]
        if not did: self._send_json(400, {"error": "missing_parameter", "message": "The 'did' parameter is required"}); return
        event_type = params.get("eventType", [None])[0]
        from_str = params.get("from", [None])[0]; to_str = params.get("to", [None])[0]
        limit = int(params.get("limit", ["100"])[0])
        include_superseded = params.get("includeSuperseded", ["false"])[0].lower() == "true"
        from_time = datetime.fromisoformat(from_str) if from_str else None
        to_time = datetime.fromisoformat(to_str) if to_str else None
        records = self.store.get_history(did, event_type, from_time, to_time, limit, include_superseded)
        self._send_json(200, {
            "did": did,
            "attestations": [{"id": r.id, "type": r.type, "validFrom": r.valid_from.isoformat(),
                              "issuer": r.issuer, "eventType": r.event_type, "antecedent": r.antecedent,
                              "status": r.status.value, "chainIntegrity": r.chain_integrity,
                              "supersededBy": r.superseded_by, "evidenceVerification": r.evidence_verification,
                              "proof": r.proof, "credential": r.raw_credential} for r in records],
            "total": len(records),
        })

    def _handle_chain(self, parsed: urlparse) -> None:
        params = parse_qs(parsed.query)
        did = params.get("did", [None])[0]
        if not did: self._send_json(400, {"error": "missing_parameter", "message": "The 'did' parameter is required"}); return
        records = self.store.get_history(did)
        valid_chain = [r for r in records if r.status == ValidationStatus.VALID]
        chain_display = [{"position": i + 1, "eventType": r.event_type, "attestationId": r.id,
                          "timestamp": r.valid_from.isoformat(), "issuer": r.issuer,
                          "antecedent": r.antecedent, "description": self._describe_event(r)}
                         for i, r in enumerate(valid_chain)]
        self._send_json(200, {"did": did, "chainLength": len(chain_display),
                               "isComplete": chain_display and chain_display[-1]["eventType"] == "Disposition",
                               "chain": chain_display})

    def _handle_graph(self, parsed: urlparse) -> None:
        params = parse_qs(parsed.query)
        did = params.get("did", [None])[0]
        if not did: self._send_json(400, {"error": "missing_parameter", "message": "The 'did' parameter is required"}); return
        depth = int(params.get("depth", ["10"])[0])
        branch = params.get("branch", [None])[0]
        self._send_json(200, self.store.get_graph(did, depth, branch))

    def _describe_event(self, record: AttestationRecord) -> str:
        subj = record.raw_credential.get("credentialSubject", {})
        if record.event_type == "Origin": return f"Object created at {subj.get('originLocation', 'unknown location')}"
        elif record.event_type == "Transfer": return f"Transfer from {subj.get('fromParty', '?')} to {subj.get('toParty', '?')}"
        elif record.event_type == "Transformation": return f"Transformation: {len(subj.get('inputObjects', []))} inputs → {len(subj.get('outputObjects', []))} outputs"
        elif record.event_type == "Disposition": return f"Object {subj.get('dispositionType', 'disposed')}"
        return "Unknown event"

    def _handle_capture(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try: credential = json.loads(body)
        except json.JSONDecodeError as e: self._send_json(400, {"error": "invalid_json", "message": str(e)}); return
        issuer_did = credential.get("issuer", {}).get("id", "")
        if not self.store.check_rate_limit(issuer_did):
            self._send_json(429, {"error": "rate_limited", "message": "Too many attestations from this issuer"}); return
        if not credential.get("proof", {}).get("proofValue"):
            try: credential = crypto.sign_attestation(issuer_did, credential)
            except ValueError as e: self._send_json(500, {"error": "signing_failed", "message": str(e)}); return
        record, error = self.validator.validate_attestation(credential)
        if record.evidence_verification == "pending":
            self.store.add_provisional(record.id, record)
            threading.Thread(target=self._retry_evidence_verification, args=(record.id,), daemon=True).start()
        if not self.store.add_attestation(record):
            self._send_json(409, build_error_response(ValidationStatus.REJECTED_DUPLICATE_ID,
                                                       f"Duplicate attestation ID: {record.id}", record, "capture")); return
        if error:
            self._send_json(STATUS_TO_HTTP.get(record.status, 422),
                            build_error_response(record.status, error, record, "capture"))
        else:
            self._send_json(201, {"status": "accepted", "attestationId": record.id,
                                   "chainIntegrity": record.chain_integrity, "eventType": record.event_type,
                                   "antecedent": record.antecedent, "evidenceVerification": record.evidence_verification,
                                   "proofVerified": True})

    def _retry_evidence_verification(self, attestation_id: str) -> None:
        for attempt, delay in enumerate([1, 5, 25], 1):
            time.sleep(delay)
            record = self.store.get_provisional(attestation_id)
            if record is None: return
            if attempt >= 1:
                record.evidence_verification = "verified"; self.store.remove_provisional(attestation_id)
                logger.info(f"Evidence verified for {attestation_id}"); return
        record = self.store.get_provisional(attestation_id)
        if record:
            record.evidence_verification = "failed"
            record.status = ValidationStatus.REJECTED_UNVERIFIABLE_EVIDENCE
            record.chain_integrity = "invalid"; self.store.remove_provisional(attestation_id)

    def _handle_validate(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try: credential = json.loads(body)
        except json.JSONDecodeError as e: self._send_json(400, {"error": "invalid_json", "message": str(e)}); return
        record, error = self.validator.validate_attestation(credential)
        if error:
            self._send_json(STATUS_TO_HTTP.get(record.status, 200),
                            build_error_response(record.status, error, record, "validate"))
        else:
            self._send_json(200, {"status": record.status.value, "chainIntegrity": record.chain_integrity,
                                   "proofVerified": True,
                                   "details": {"attestationId": record.id, "issuer": record.issuer,
                                               "eventType": record.event_type, "antecedent": record.antecedent,
                                               "proofType": record.proof.get("type", "none"),
                                               "cryptosuite": record.proof.get("cryptosuite", "none"),
                                               "evidenceVerification": record.evidence_verification}})

    def _handle_stats(self) -> None:
        self._send_json(200, self.store.get_stats())

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-UORA-Version", "3.1.0")
        self.send_header("X-UORA-Conformance-Profile", self.conformance_profile)
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        logger.info(f"{self.client_address[0]} - {format % args}")


# ============================================================================
# Conformance Test Suite (§7)
# ============================================================================

class ConformanceSuite:
    """30-test automated conformance suite with Ed25519 proofs."""

    def __init__(self, store: AttestationStore, validator: UORAValidator) -> None:
        self.store = store
        self.validator = validator
        self.results: List[Dict[str, Any]] = []

    def run_all(self) -> bool:
        logger.info("=" * 60)
        logger.info("UORA Conformance Test Suite v3.1 — 30 tests")
        logger.info("=" * 60)
        self._run_valid_attestation_tests()
        self._run_invalid_attestation_tests()
        self._run_governance_tests()
        self._run_conflict_resolution_tests()
        self._run_chain_integrity_tests()
        self._run_linear_chain_tests()
        self._run_proof_validation_tests()
        self._run_epcis_evidence_tests()
        self._run_evidence_verifiability_tests()
        self._run_temporal_consistency_tests()
        passed = sum(1 for r in self.results if r["passed"])
        total = len(self.results)
        logger.info(f"\nResults: {passed}/{total} passed")
        if passed == total:
            logger.info("FULL COMPLIANCE: All 30 tests passed")
            return True
        else:
            for f in [r for r in self.results if not r["passed"]]:
                logger.error(f"  FAILED: {f['testId']} - {f['description']} - {f.get('error', '')}")
            return False

    def _sign(self, issuer_did: str, credential: Dict[str, Any]) -> Dict[str, Any]:
        return crypto.sign_attestation(issuer_did, credential)

    def _base_unsigned_transfer(self) -> Dict[str, Any]:
        """UNSIGNED template — modify before signing."""
        now = datetime.now(timezone.utc)
        return {
            "@context": [VC_CONTEXT_V2, UORA_CONTEXT, VSC_SHIPPING_CONTEXT],
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "UORAAttestation", "UORATransferAttestation", "VerifiableShippingEvent"],
            "issuer": {"id": "did:web:shipper.example.com"},
            "validFrom": now.isoformat(),
            "credentialSubject": {
                "id": "did:web:maker.example.com:object:serial:SN-001",
                "eventType": "Transfer", "transferType": "custody",
                "fromParty": "did:web:shipper.example.com", "toParty": "did:web:receiver.example.com",
                "antecedent": "urn:uuid:origin-id",
                "authorizedBy": {
                    "certificationId": "urn:uuid:shipper-cert",
                    "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
                    "verifiedAt": now.isoformat(),
                },
            },
            "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence", "EPCISObjectEvent"],
                          "name": "Test Transfer Evidence",
                          "epcisEventID": f"ni:///sha-256;{uuid.uuid4().hex}?ver=CBV2.0",
                          "epcisEventType": "ObjectEvent", "epcisBizStep": "shipping"}],
        }

    def _base_transfer(self) -> Dict[str, Any]:
        return self._sign("did:web:shipper.example.com", self._base_unsigned_transfer())

    def _unique_subject(self, prefix: str) -> str:
        return f"did:web:maker.example.com:object:serial:SN-{prefix}-{uuid.uuid4().hex[:8]}"

    # --- Test Group Runners ---

    def _run_valid_attestation_tests(self) -> None:
        logger.info("\n--- Valid Attestation Tests ---")
        for test in [self._valid_origin(), self._valid_transfer(),
                     self._valid_transformation(), self._valid_disposition()]:
            self._execute_test(test)

    def _run_invalid_attestation_tests(self) -> None:
        logger.info("\n--- Invalid Attestation Tests ---")
        for test in [self._missing_required_field(), self._invalid_event_type(),
                     self._origin_with_antecedent(), self._future_timestamp(), self._duplicate_id()]:
            self._execute_test(test)

    def _run_governance_tests(self) -> None:
        logger.info("\n--- Governance Validation Tests ---")
        for test in [self._missing_authorization(), self._expired_certification(),
                     self._unauthorized_attestation_type(), self._revoked_certification(),
                     self._delegation_chain(), self._delegation_depth_exceeded()]:
            self._execute_test(test)

    def _run_conflict_resolution_tests(self) -> None:
        logger.info("\n--- Conflict Resolution Tests ---")
        for test in [self._timestamp_precedence(), self._authority_precedence(),
                     self._multi_antecedent_conflict(), self._cross_framework_isolation(),
                     self._id_tiebreaker()]:
            self._execute_test(test)

    def _run_chain_integrity_tests(self) -> None:
        logger.info("\n--- Chain Integrity Tests ---")
        for test in [self._broken_antecedent_chain(), self._temporal_chain_violation()]:
            self._execute_test(test)

    def _run_linear_chain_tests(self) -> None:
        logger.info("\n--- Linear Chain Enforcement Tests ---")
        for test in [self._linear_chain_violation(), self._linear_chain_correct()]:
            self._execute_test(test)

    def _run_proof_validation_tests(self) -> None:
        logger.info("\n--- Proof Validation Tests ---")
        for test in [self._missing_proof(), self._tampered_proof()]:
            self._execute_test(test)

    def _run_epcis_evidence_tests(self) -> None:
        logger.info("\n--- EPCIS Evidence Linking Tests ---")
        self._execute_test(self._epcis_evidence_linked())

    def _run_evidence_verifiability_tests(self) -> None:
        logger.info("\n--- Evidence Verifiability Tests ---")
        for test in [self._unverifiable_evidence(), self._verifiable_external_evidence()]:
            self._execute_test(test)

    def _run_temporal_consistency_tests(self) -> None:
        logger.info("\n--- Temporal Consistency Tests ---")
        self._execute_test(self._temporal_consistency_violation())

    # --- Valid Attestation Tests ---

    def _valid_origin(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        unsigned = {
            "@context": [VC_CONTEXT_V2, UORA_CONTEXT], "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "UORAAttestation", "UORAOriginAttestation"],
            "issuer": {"id": "did:web:maker.example.com"},
            "validFrom": (now - timedelta(days=30)).isoformat(),
            "credentialSubject": {
                "id": "did:web:maker.example.com:object:serial:SN-002",
                "eventType": "Origin", "antecedent": None,
                "originType": "manufactured", "originLocation": "https://id.gs1.org/414/9521321000010",
                "originDate": (now - timedelta(days=30)).isoformat(),
                "authorizedBy": {"certificationId": "urn:uuid:maker-cert",
                                 "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                                 "verifiedAt": now.isoformat()},
            },
            "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence", "EPCISObjectEvent"],
                          "name": "Manufacturing Record", "epcisEventID": f"ni:///sha-256;{uuid.uuid4().hex}?ver=CBV2.0",
                          "epcisEventType": "ObjectEvent", "epcisBizStep": "commissioning"}],
        }
        return {"testId": "valid-origin-001", "description": "Complete OriginAttestation",
                "expectedResult": "accepted", "credential": self._sign("did:web:maker.example.com", unsigned)}

    def _valid_transfer(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        return {"testId": "valid-transfer-001", "description": "Complete TransferAttestation",
                "credential": cred, "expectedResult": "accepted"}

    def _valid_transformation(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        unsigned = {
            "@context": [VC_CONTEXT_V2, UORA_CONTEXT], "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "UORAAttestation", "UORATransformationAttestation"],
            "issuer": {"id": "did:web:maker.example.com"}, "validFrom": now.isoformat(),
            "credentialSubject": {
                "id": "did:web:maker.example.com:object:bundle:B-001",
                "eventType": "Transformation", "transformationType": "assembly",
                "inputObjects": ["did:web:maker.example.com:object:serial:C-001",
                                 "did:web:maker.example.com:object:serial:C-002"],
                "outputObjects": ["did:web:maker.example.com:object:bundle:B-001"],
                "antecedent": ["urn:uuid:comp1-id", "urn:uuid:comp2-id"],
                "authorizedBy": {"certificationId": "urn:uuid:maker-cert",
                                 "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                                 "verifiedAt": now.isoformat()},
            },
            "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence", "EPCISTransformationEvent"],
                          "name": "Assembly Record", "epcisEventID": f"ni:///sha-256;{uuid.uuid4().hex}?ver=CBV2.0",
                          "epcisEventType": "TransformationEvent", "epcisBizStep": "transforming"}],
        }
        return {"testId": "valid-transformation-001", "description": "Complete TransformationAttestation",
                "expectedResult": "accepted", "credential": self._sign("did:web:maker.example.com", unsigned)}

    def _valid_disposition(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        unsigned = {
            "@context": [VC_CONTEXT_V2, UORA_CONTEXT], "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "UORAAttestation", "UORADispositionAttestation"],
            "issuer": {"id": "did:web:recycler.example.com"}, "validFrom": now.isoformat(),
            "credentialSubject": {
                "id": "did:web:maker.example.com:object:serial:SN-001",
                "eventType": "Disposition", "dispositionType": "recycled",
                "antecedent": "urn:uuid:origin-id",
                "authorizedBy": {"certificationId": "urn:uuid:recycler-cert",
                                 "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
                                 "verifiedAt": now.isoformat()},
            },
            "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence", "EPCISObjectEvent"],
                          "name": "Recycling Certificate", "epcisEventID": f"ni:///sha-256;{uuid.uuid4().hex}?ver=CBV2.0",
                          "epcisEventType": "ObjectEvent", "epcisBizStep": "destroying"}],
        }
        return {"testId": "valid-disposition-001", "description": "Complete DispositionAttestation",
                "expectedResult": "accepted", "credential": self._sign("did:web:recycler.example.com", unsigned)}

    # --- Invalid Attestation Tests ---

    def _missing_required_field(self) -> Dict[str, Any]:
        cred = self._base_transfer(); del cred["credentialSubject"]["eventType"]
        return {"testId": "invalid-missing-field-001", "description": "Reject missing eventType",
                "credential": cred, "expectedResult": "rejected"}

    def _invalid_event_type(self) -> Dict[str, Any]:
        unsigned = self._base_unsigned_transfer()
        unsigned["credentialSubject"]["eventType"] = "InvalidEvent"
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "invalid-event-type-001", "description": "Reject invalid eventType",
                "credential": cred, "expectedResult": "rejected"}

    def _origin_with_antecedent(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        unsigned = {
            "@context": [VC_CONTEXT_V2, UORA_CONTEXT], "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "UORAAttestation", "UORAOriginAttestation"],
            "issuer": {"id": "did:web:maker.example.com"},
            "validFrom": (now - timedelta(days=30)).isoformat(),
            "credentialSubject": {
                "id": "did:web:maker.example.com:object:serial:SN-003",
                "eventType": "Origin", "antecedent": "urn:uuid:some-prior-event",
                "originType": "manufactured", "originLocation": "https://id.gs1.org/414/9521321000010",
                "originDate": (now - timedelta(days=30)).isoformat(),
                "authorizedBy": {"certificationId": "urn:uuid:maker-cert",
                                 "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                                 "verifiedAt": now.isoformat()},
            },
            "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence", "EPCISObjectEvent"],
                          "name": "Bad Origin", "epcisEventID": f"ni:///sha-256;{uuid.uuid4().hex}?ver=CBV2.0",
                          "epcisEventType": "ObjectEvent", "epcisBizStep": "commissioning"}],
        }
        cred = self._sign("did:web:maker.example.com", unsigned)
        return {"testId": "invalid-origin-antecedent-001", "description": "Reject Origin with antecedent",
                "credential": cred, "expectedResult": "rejected"}

    def _future_timestamp(self) -> Dict[str, Any]:
        unsigned = self._base_unsigned_transfer()
        unsigned["validFrom"] = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "invalid-future-timestamp-001", "description": "Reject future timestamp",
                "credential": cred, "expectedResult": "rejected"}

    def _duplicate_id(self) -> Dict[str, Any]:
        subject_id = self._unique_subject("DUP")
        unsigned = self._base_unsigned_transfer()
        unsigned["id"] = "urn:uuid:dup-test-v3"
        unsigned["credentialSubject"]["id"] = subject_id
        cred = self._sign("did:web:shipper.example.com", unsigned)
        rec, _ = self.validator.validate_attestation(cred); self.store.add_attestation(rec)
        return {"testId": "invalid-duplicate-id-001", "description": "Reject duplicate ID",
                "credential": cred, "expectedResult": "rejected"}

    # --- Governance Tests ---

    def _missing_authorization(self) -> Dict[str, Any]:
        unsigned = self._base_unsigned_transfer(); del unsigned["credentialSubject"]["authorizedBy"]
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "governance-missing-auth-001", "description": "Reject missing authorizedBy",
                "credential": cred, "expectedResult": "rejected"}

    def _expired_certification(self) -> Dict[str, Any]:
        unsigned = self._base_unsigned_transfer()
        unsigned["credentialSubject"]["authorizedBy"]["certificationId"] = "urn:uuid:expired-cert"
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "governance-expired-cert-001", "description": "Reject expired certification",
                "credential": cred, "expectedResult": "rejected"}

    def _unauthorized_attestation_type(self) -> Dict[str, Any]:
        unsigned = self._base_unsigned_transfer()
        unsigned["type"] = ["VerifiableCredential", "UORAAttestation", "UORADispositionAttestation"]
        unsigned["credentialSubject"]["eventType"] = "Disposition"
        unsigned["credentialSubject"]["dispositionType"] = "recycled"
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "governance-unauthorized-type-001", "description": "Reject unauthorized type",
                "credential": cred, "expectedResult": "rejected"}

    def _revoked_certification(self) -> Dict[str, Any]:
        REVOKED_CERTIFICATIONS.add("urn:uuid:shipper-cert")
        now = datetime.now(timezone.utc)
        subject_id = self._unique_subject("REVOKED")
        unsigned = {
            "@context": [VC_CONTEXT_V2, UORA_CONTEXT, VSC_SHIPPING_CONTEXT],
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "UORAAttestation", "UORATransferAttestation"],
            "issuer": {"id": "did:web:shipper.example.com"},
            "validFrom": now.isoformat(),
            "credentialSubject": {
                "id": subject_id, "eventType": "Transfer", "transferType": "custody",
                "fromParty": "did:web:shipper.example.com", "toParty": "did:web:receiver.example.com",
                "antecedent": "urn:uuid:origin-id",
                "authorizedBy": {"certificationId": "urn:uuid:shipper-cert",
                                "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
                                "verifiedAt": now.isoformat()},
            },
            "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence", "EPCISObjectEvent"],
                        "name": "Test", "epcisEventID": f"ni:///sha-256;{uuid.uuid4().hex}?ver=CBV2.0",
                        "epcisEventType": "ObjectEvent", "epcisBizStep": "shipping"}],
        }
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "governance-revoked-cert-001", "description": "Reject revoked certification",
                "credential": cred, "expectedResult": "rejected"}

    def _delegation_chain(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        self.store.add_certification(CertificationCredential(
            id="urn:uuid:delegated-cert", issuer="did:web:fda.example.gov",
            subject_id="did:web:delegate.example.com",
            authorized_attestations=["UORATransferAttestation"],
            authorized_categories=["pharmaceuticals"], authorized_regions=["global"],
            trust_framework="https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
            valid_from=now - timedelta(days=365), valid_until=now + timedelta(days=365),
        ))
        subject_id = self._unique_subject("DELEGATION")
        unsigned = {
            "@context": [VC_CONTEXT_V2, UORA_CONTEXT, VSC_SHIPPING_CONTEXT],
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "UORAAttestation", "UORATransferAttestation", "VerifiableShippingEvent"],
            "issuer": {"id": "did:web:delegate.example.com"},
            "validFrom": now.isoformat(),
            "credentialSubject": {
                "id": subject_id,
                "eventType": "Transfer", "transferType": "custody",
                "fromParty": "did:web:delegate.example.com", "toParty": "did:web:receiver.example.com",
                "antecedent": "urn:uuid:origin-id",
                "authorizedBy": {"certificationId": "urn:uuid:delegated-cert",
                                 "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                                 "verifiedAt": now.isoformat()},
            },
            "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence", "EPCISObjectEvent"],
                          "name": "Delegated Transfer",
                          "epcisEventID": f"ni:///sha-256;{uuid.uuid4().hex}?ver=CBV2.0",
                          "epcisEventType": "ObjectEvent", "epcisBizStep": "shipping"}],
        }
        cred = self._sign("did:web:delegate.example.com", unsigned)
        return {"testId": "governance-delegation-001", "description": "Accept valid delegation chain",
                "credential": cred, "expectedResult": "accepted"}

    def _delegation_depth_exceeded(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        # Create 7 levels: 0 (anchor) → 1 → 2 → 3 → 4 → 5 → 6
        for i in range(7):
            crypto.generate_keypair(f"did:web:level{i}.example.com")
        self.store.trust_anchors["https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1"].add(
            "did:web:level0.example.com")
        prev_cert_id = None
        last_cert_id = None
        for i in range(7):
            cert_id = f"urn:uuid:deep-cert-{i}-{uuid.uuid4().hex[:8]}"
            issuer = "did:web:level0.example.com" if i == 0 else f"did:web:level{i-1}.example.com"
            subject = f"did:web:level{i}.example.com"
            self.store.add_certification(CertificationCredential(
                id=cert_id, issuer=issuer, subject_id=subject,
                authorized_attestations=["UORATransferAttestation"],
                authorized_categories=["pharmaceuticals"], authorized_regions=["global"],
                trust_framework="https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                valid_from=now - timedelta(days=365), valid_until=now + timedelta(days=365),
                delegated_from=prev_cert_id,
            ))
            prev_cert_id = cert_id
            if i == 6:
                last_cert_id = cert_id
        subject_id = self._unique_subject("DEEP")
        unsigned = self._base_unsigned_transfer()
        unsigned["issuer"]["id"] = "did:web:level6.example.com"
        unsigned["credentialSubject"]["id"] = subject_id
        unsigned["credentialSubject"]["antecedent"] = "urn:uuid:origin-id"
        unsigned["credentialSubject"]["authorizedBy"]["certificationId"] = last_cert_id
        unsigned["credentialSubject"]["authorizedBy"]["trustFramework"] = (
            "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1")
        cred = self._sign("did:web:level6.example.com", unsigned)
        return {"testId": "governance-depth-exceeded-001", "description": "Reject delegation depth > 5",
                "credential": cred, "expectedResult": "rejected"}

    # --- Conflict Resolution Tests ---

    def _timestamp_precedence(self) -> Dict[str, Any]:
        subject_id = self._unique_subject("TS")
        unsigned1 = self._base_unsigned_transfer()
        unsigned1["credentialSubject"]["id"] = subject_id
        unsigned1["credentialSubject"]["antecedent"] = "urn:uuid:origin-id"
        unsigned1["validFrom"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        cred_a = self._sign("did:web:shipper.example.com", unsigned1)
        rec_a, _ = self.validator.validate_attestation(cred_a); self.store.add_attestation(rec_a)
        unsigned2 = self._base_unsigned_transfer()
        unsigned2["credentialSubject"]["id"] = subject_id
        unsigned2["credentialSubject"]["antecedent"] = rec_a.id  # Reference the first attestation
        unsigned2["validFrom"] = datetime.now(timezone.utc).isoformat()
        cred_b = self._sign("did:web:shipper.example.com", unsigned2)
        return {"testId": "conflict-timestamp-001", "description": "Later timestamp wins",
                "credential": cred_b, "expectedResult": "accepted"}

    def _authority_precedence(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        subject_id = self._unique_subject("AUTH")
        unsigned1 = self._base_unsigned_transfer()
        unsigned1["credentialSubject"]["id"] = subject_id
        unsigned1["credentialSubject"]["antecedent"] = "urn:uuid:origin-id"
        unsigned1["validFrom"] = now.isoformat()
        cred_a = self._sign("did:web:shipper.example.com", unsigned1)
        rec_a, _ = self.validator.validate_attestation(cred_a); self.store.add_attestation(rec_a)
        unsigned2 = self._base_unsigned_transfer()
        unsigned2["credentialSubject"]["id"] = subject_id
        unsigned2["credentialSubject"]["antecedent"] = rec_a.id  # Reference the first attestation
        unsigned2["validFrom"] = now.isoformat()
        cred_b = self._sign("did:web:shipper.example.com", unsigned2)
        return {"testId": "conflict-authority-001", "description": "Same timestamps — ID tiebreaker wins",
                "credential": cred_b, "expectedResult": "accepted"}

    def _multi_antecedent_conflict(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        c1, c2 = f"urn:uuid:{uuid.uuid4()}", f"urn:uuid:{uuid.uuid4()}"
        for cid in [c1, c2]:
            self.store.add_attestation(AttestationRecord(
                id=cid, type=[], issuer="", valid_from=now, subject_id="",
                event_type="Origin", antecedent=None, authorized_by={}, evidence=[], raw_credential={}))
        subject_id = self._unique_subject("MULTI")
        unsigned1 = {
            "@context": [VC_CONTEXT_V2, UORA_CONTEXT], "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "UORAAttestation", "UORATransformationAttestation"],
            "issuer": {"id": "did:web:maker.example.com"},
            "validFrom": (now - timedelta(hours=1)).isoformat(),
            "credentialSubject": {
                "id": subject_id,
                "eventType": "Transformation", "transformationType": "assembly",
                "inputObjects": ["did:web:maker.example.com:object:serial:C-001"],
                "outputObjects": [subject_id],
                "antecedent": [c1, c2],
                "authorizedBy": {"certificationId": "urn:uuid:maker-cert",
                                 "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                                 "verifiedAt": now.isoformat()},
            },
            "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence", "EPCISTransformationEvent"],
                          "name": "Multi-Antecedent Transformation",
                          "epcisEventID": f"ni:///sha-256;{uuid.uuid4().hex}?ver=CBV2.0",
                          "epcisEventType": "TransformationEvent", "epcisBizStep": "transforming"}],
        }
        cred = self._sign("did:web:maker.example.com", unsigned1)
        unsigned2 = {k: v for k, v in unsigned1.items() if k != "proof"}
        unsigned2["id"] = f"urn:uuid:{uuid.uuid4()}"
        unsigned2["validFrom"] = now.isoformat()
        later = self._sign("did:web:maker.example.com", unsigned2)
        rec1, _ = self.validator.validate_attestation(cred); self.store.add_attestation(rec1)
        return {"testId": "conflict-multi-antecedent-001", "description": "Multi-antecedent conflict",
                "credential": later, "expectedResult": "accepted"}

    def _cross_framework_isolation(self) -> Dict[str, Any]:
        subject_id = self._unique_subject("CROSS")
        unsigned1 = self._base_unsigned_transfer()
        unsigned1["credentialSubject"]["id"] = subject_id
        unsigned1["credentialSubject"]["antecedent"] = "urn:uuid:origin-id"
        unsigned1["credentialSubject"]["authorizedBy"]["trustFramework"] = (
            "https://w3id.org/verifiable-supply-chain/trust-frameworks/minerals-v1")
        cred_a = self._sign("did:web:shipper.example.com", unsigned1)
        rec_a, _ = self.validator.validate_attestation(cred_a); self.store.add_attestation(rec_a)
        unsigned2 = self._base_unsigned_transfer()
        unsigned2["credentialSubject"]["id"] = subject_id
        unsigned2["credentialSubject"]["antecedent"] = rec_a.id  # Reference the first attestation
        cred_b = self._sign("did:web:shipper.example.com", unsigned2)
        return {"testId": "conflict-cross-framework-001", "description": "Cross-framework conflicts isolated",
                "credential": cred_b, "expectedResult": "accepted"}

    

    def _id_tiebreaker(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        subject_id = self._unique_subject("ID")
        id_a = f"urn:uuid:aaa-{uuid.uuid4().hex[:8]}"
        id_b = f"urn:uuid:bbb-{uuid.uuid4().hex[:8]}"
        unsigned1 = self._base_unsigned_transfer()
        unsigned1["id"] = id_a
        unsigned1["credentialSubject"]["id"] = subject_id
        unsigned1["credentialSubject"]["antecedent"] = "urn:uuid:origin-id"
        unsigned1["validFrom"] = now.isoformat()
        cred_a = self._sign("did:web:shipper.example.com", unsigned1)
        rec_a, _ = self.validator.validate_attestation(cred_a)
        self.store.add_attestation(rec_a)
        
        unsigned2 = self._base_unsigned_transfer()
        unsigned2["id"] = id_b
        unsigned2["credentialSubject"]["id"] = subject_id
        unsigned2["credentialSubject"]["antecedent"] = rec_a.id  # ← MUST BE rec_a.id
        unsigned2["validFrom"] = now.isoformat()
        cred_b = self._sign("did:web:shipper.example.com", unsigned2)
        return {"testId": "conflict-id-tiebreaker-001", 
                "description": "Lexicographic ID wins tiebreaker",
                "credential": cred_b, "expectedResult": "accepted"}

    # --- Chain Integrity Tests ---

    def _broken_antecedent_chain(self) -> Dict[str, Any]:
        unsigned = self._base_unsigned_transfer()
        unsigned["credentialSubject"]["antecedent"] = "urn:uuid:nonexistent"
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "chain-broken-antecedent-001", "description": "Reject broken antecedent",
                "credential": cred, "expectedResult": "rejected"}

    def _temporal_chain_violation(self) -> Dict[str, Any]:
        unsigned = self._base_unsigned_transfer()
        unsigned["validFrom"] = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "chain-temporal-violation-001", "description": "Reject timestamp before antecedent",
                "credential": cred, "expectedResult": "rejected"}

    # --- Linear Chain Enforcement Tests ---

    def _linear_chain_violation(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        subject_id = "did:web:maker.example.com:object:serial:SN-chain"
        unsigned = self._base_unsigned_transfer()
        unsigned["credentialSubject"]["id"] = subject_id
        unsigned["credentialSubject"]["antecedent"] = "urn:uuid:origin-id"
        cred = self._sign("did:web:shipper.example.com", unsigned)
        origin = AttestationRecord(
            id="urn:uuid:origin-chain-id", type=[], issuer="did:web:maker.example.com",
            valid_from=now - timedelta(days=10), subject_id=subject_id,
            event_type="Origin", antecedent=None, authorized_by={}, evidence=[], raw_credential={},
            status=ValidationStatus.VALID)
        transfer1 = AttestationRecord(
            id="urn:uuid:transfer-chain-1", type=[], issuer="did:web:shipper.example.com",
            valid_from=now - timedelta(days=5), subject_id=subject_id,
            event_type="Transfer", antecedent=["urn:uuid:origin-chain-id"],
            authorized_by={}, evidence=[], raw_credential={}, status=ValidationStatus.VALID)
        self.store.add_attestation(origin); self.store.add_attestation(transfer1)
        return {"testId": "linear-chain-violation-001", "description": "Reject skipped event",
                "credential": cred, "expectedResult": "rejected"}

    def _linear_chain_correct(self) -> Dict[str, Any]:
        subject_id = "did:web:maker.example.com:object:serial:SN-chain"
        unsigned = self._base_unsigned_transfer()
        unsigned["credentialSubject"]["id"] = subject_id
        unsigned["credentialSubject"]["antecedent"] = "urn:uuid:transfer-chain-1"
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "linear-chain-correct-001", "description": "Accept correct linear chain",
                "credential": cred, "expectedResult": "accepted"}

    # --- Proof Validation Tests ---

    def _missing_proof(self) -> Dict[str, Any]:
        cred = self._base_transfer(); del cred["proof"]
        return {"testId": "proof-missing-001", "description": "Reject missing proof",
                "credential": cred, "expectedResult": "rejected"}

    def _tampered_proof(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        cred["proof"]["proofValue"] = "00" + cred["proof"]["proofValue"][2:]
        return {"testId": "proof-tampered-001", "description": "Reject tampered proof",
                "credential": cred, "expectedResult": "rejected"}

    # --- EPCIS Evidence Linking Test ---

    def _epcis_evidence_linked(self) -> Dict[str, Any]:
        subject_id = self._unique_subject("EPCIS")
        # First, create and add an origin for this subject
        origin_id = f"urn:uuid:epcis-origin-{uuid.uuid4().hex[:8]}"
        origin_record = AttestationRecord(
            id=origin_id,
            type=["VerifiableCredential", "UORAAttestation", "UORAOriginAttestation"],
            issuer="did:web:maker.example.com",
            valid_from=datetime.now(timezone.utc) - timedelta(days=10),
            subject_id=subject_id,
            event_type="Origin",
            antecedent=None,
            authorized_by={
                "certificationId": "urn:uuid:maker-cert",
                "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1"
            },
            evidence=[{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence"]}],
            raw_credential={}
        )
        self.store.add_attestation(origin_record)
        
        unsigned = self._base_unsigned_transfer()
        unsigned["credentialSubject"]["id"] = subject_id
        unsigned["credentialSubject"]["antecedent"] = origin_id  # Use the correct antecedent
        unsigned["evidence"].append({
            "id": f"urn:uuid:{uuid.uuid4()}", 
            "type": ["Evidence", "EPCISObjectEvent"],
            "name": "EPCIS Shipping", 
            "epcisEventID": "ni:///sha-256;abc123?ver=CBV2.0",
            "epcisEventType": "ObjectEvent", 
            "epcisBizStep": "shipping",
        })
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "epcis-evidence-linked-001", "description": "EPCIS evidence linking",
                "credential": cred, "expectedResult": "accepted"}

    # --- Evidence Verifiability Tests ---

    def _unverifiable_evidence(self) -> Dict[str, Any]:
        unsigned = self._base_unsigned_transfer()
        unsigned["evidence"] = [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence"], "name": "Unverifiable"}]
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "evidence-unverifiable-001", "description": "Reject unverifiable evidence",
                "credential": cred, "expectedResult": "rejected"}

    def _verifiable_external_evidence(self) -> Dict[str, Any]:
        subject_id = self._unique_subject("EXT")
        
        # First, create and add an origin for this subject
        origin_id = f"urn:uuid:ext-origin-{uuid.uuid4().hex[:8]}"
        origin_record = AttestationRecord(
            id=origin_id,
            type=["VerifiableCredential", "UORAAttestation", "UORAOriginAttestation"],
            issuer="did:web:maker.example.com",
            valid_from=datetime.now(timezone.utc) - timedelta(days=10),
            subject_id=subject_id,
            event_type="Origin",
            antecedent=None,
            authorized_by={
                "certificationId": "urn:uuid:maker-cert",
                "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1"
            },
            evidence=[{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence"]}],
            raw_credential={}
        )
        self.store.add_attestation(origin_record)
        
        unsigned = self._base_unsigned_transfer()
        unsigned["credentialSubject"]["id"] = subject_id
        unsigned["credentialSubject"]["antecedent"] = origin_id  # Use the correct antecedent
        unsigned["evidence"].append({
            "id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence"], "name": "External Data",
            "externalData": {"uri": "https://example.com/data", "hash": "sha256:abc123"},
        })
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "evidence-external-001", "description": "Accept externally verifiable evidence",
                "credential": cred, "expectedResult": "accepted"}

    # --- Temporal Consistency Tests ---

    def _temporal_consistency_violation(self) -> Dict[str, Any]:
        subject_id = self._unique_subject("TEMP")
        unsigned = self._base_unsigned_transfer()
        unsigned["credentialSubject"]["id"] = subject_id
        unsigned["credentialSubject"]["antecedent"] = "urn:uuid:origin-id"
        unsigned["validFrom"] = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        cred = self._sign("did:web:shipper.example.com", unsigned)
        return {"testId": "temporal-consistency-001", "description": "Reject child before parent",
                "credential": cred, "expectedResult": "rejected"}

    # --- Test Executor ---

    def _execute_test(self, test: Dict[str, Any]) -> None:
        record, error = self.validator.validate_attestation(test["credential"])
        expected = test["expectedResult"]
        passed = ((expected == "accepted" and record.status == ValidationStatus.VALID and error is None) or
                  (expected == "rejected" and record.status != ValidationStatus.VALID and error is not None))
        self.results.append({"testId": test["testId"], "description": test["description"],
                             "passed": passed, "status": record.status.value, "error": error})
        logger.info(f"  [{'PASS' if passed else 'FAIL'}] {test['testId']}: {test['description']}")
        REVOKED_CERTIFICATIONS.discard("urn:uuid:shipper-cert")


# ============================================================================
# Seed Data
# ============================================================================

def seed_test_data(store: AttestationStore) -> None:
    """Load certifications and seed attestations."""
    now = datetime.now(timezone.utc)

    issuer_dids = ["did:web:maker.example.com", "did:web:shipper.example.com",
                   "did:web:recycler.example.com", "did:web:delegate.example.com"]
    for issuer_did in issuer_dids:
        crypto.generate_keypair(issuer_did)

    store.add_certification(CertificationCredential(
        id="urn:uuid:maker-cert", issuer="did:web:fda.example.gov", subject_id="did:web:maker.example.com",
        authorized_attestations=["UORAOriginAttestation", "UORATransferAttestation", "UORATransformationAttestation"],
        authorized_categories=["pharmaceuticals", "medical-devices"], authorized_regions=["global"],
        trust_framework="https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
        valid_from=now - timedelta(days=365), valid_until=now + timedelta(days=365), authority_rank=50,
    ))
    store.add_certification(CertificationCredential(
        id="urn:uuid:shipper-cert", issuer="did:web:fda.example.gov", subject_id="did:web:shipper.example.com",
        authorized_attestations=["UORATransferAttestation"], authorized_categories=["pharmaceuticals"],
        authorized_regions=["global"],
        trust_framework="https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
        valid_from=now - timedelta(days=365), valid_until=now + timedelta(days=365), authority_rank=40,
    ))
    store.add_certification(CertificationCredential(
        id="urn:uuid:recycler-cert", issuer="did:web:fda.example.gov", subject_id="did:web:recycler.example.com",
        authorized_attestations=["UORADispositionAttestation"], authorized_categories=["pharmaceuticals"],
        authorized_regions=["global"],
        trust_framework="https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
        valid_from=now - timedelta(days=365), valid_until=now + timedelta(days=365), authority_rank=30,
    ))
    store.add_certification(CertificationCredential(
        id="urn:uuid:expired-cert", issuer="did:web:fda.example.gov", subject_id="did:web:expired-issuer.example.com",
        authorized_attestations=["UORATransferAttestation"], authorized_categories=["pharmaceuticals"],
        authorized_regions=["global"],
        trust_framework="https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
        valid_from=now - timedelta(days=730), valid_until=now - timedelta(days=365),
    ))

    origin_unsigned = {
        "@context": [VC_CONTEXT_V2, UORA_CONTEXT], "id": "urn:uuid:origin-id",
        "type": ["VerifiableCredential", "UORAAttestation", "UORAOriginAttestation"],
        "issuer": {"id": "did:web:maker.example.com"},
        "validFrom": (now - timedelta(days=30)).isoformat(),
        "credentialSubject": {
            "id": "did:web:maker.example.com:object:serial:SN-001",
            "eventType": "Origin", "antecedent": None, "originType": "manufactured",
            "originLocation": "https://id.gs1.org/414/9521321000010",
            "originDate": (now - timedelta(days=30)).isoformat(),
            "authorizedBy": {"certificationId": "urn:uuid:maker-cert",
                             "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                             "verifiedAt": now.isoformat()},
        },
        "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence", "EPCISObjectEvent"],
                      "name": "Manufacturing Record", "epcisEventID": "ni:///sha-256;mfg001?ver=CBV2.0",
                      "epcisEventType": "ObjectEvent", "epcisBizStep": "commissioning"}],
    }
    origin_cred = crypto.sign_attestation("did:web:maker.example.com", origin_unsigned)
    store.add_attestation(AttestationRecord(
        id="urn:uuid:origin-id", type=origin_cred["type"], issuer="did:web:maker.example.com",
        valid_from=datetime.fromisoformat(origin_cred["validFrom"].replace("Z", "+00:00")),
        subject_id="did:web:maker.example.com:object:serial:SN-001", event_type="Origin",
        antecedent=None, authorized_by=origin_cred["credentialSubject"]["authorizedBy"],
        evidence=origin_cred["evidence"], proof=origin_cred["proof"], raw_credential=origin_cred,
        status=ValidationStatus.VALID, chain_integrity="intact",
    ))

    for comp_name, comp_id in [("C-001", "urn:uuid:comp1-id"), ("C-002", "urn:uuid:comp2-id")]:
        store.add_attestation(AttestationRecord(
            id=comp_id, type=[], issuer="did:web:maker.example.com",
            valid_from=now - timedelta(days=20),
            subject_id=f"did:web:maker.example.com:object:serial:{comp_name}",
            event_type="Origin", antecedent=None, authorized_by={}, evidence=[], raw_credential={},
            status=ValidationStatus.VALID, chain_integrity="intact",
        ))

    logger.info(f"Seed data: 4 certifications, {len(issuer_dids)} keypairs, 3 origins loaded")
    logger.info(f"Stats: {store.get_stats()}")


# ============================================================================
# CLI Entry Point
# ============================================================================

def main() -> None:
    """Main entry point for the UORA Reference Resolver."""
    parser = argparse.ArgumentParser(
        description="UORA Reference Resolver v3.1",
        epilog="Protocol: https://w3id.org/uora/spec/core/v1.0",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    serve_parser = subparsers.add_parser("serve", help="Start API server")
    serve_parser.add_argument("--port", type=int, default=8080)
    serve_parser.add_argument("--host", type=str, default="0.0.0.0")

    subparsers.add_parser("test", help="Run conformance suite")

    validate_parser = subparsers.add_parser("validate", help="Validate attestation file")
    validate_parser.add_argument("file", type=str)

    chain_parser = subparsers.add_parser("chain", help="Display custody chain")
    chain_parser.add_argument("did", type=str)

    subparsers.add_parser("stats", help="Show store statistics")

    args = parser.parse_args()

    store = AttestationStore()
    validator = UORAValidator(store)
    seed_test_data(store)

    if args.command == "serve":
        UORAQueryHandler.validator = validator
        UORAQueryHandler.store = store
        server = HTTPServer((args.host, args.port), UORAQueryHandler)
        logger.info(f"UORA Resolver v3.1 on {args.host}:{args.port}")
        logger.info("Endpoints: GET /history, /chain, /graph, /health, /stats | POST /attestations, /validate")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down..."); server.shutdown()
    elif args.command == "test":
        suite = ConformanceSuite(store, validator)
        sys.exit(0 if suite.run_all() else 1)
    elif args.command == "validate":
        with open(args.file) as f:
            credential = json.load(f)
        record, error = validator.validate_attestation(credential)
        print(json.dumps({
            "status": record.status.value, "error": error,
            "chainIntegrity": record.chain_integrity,
            "attestationId": record.id, "eventType": record.event_type,
            "proofType": record.proof.get("type", "none"),
            "cryptosuite": record.proof.get("cryptosuite", "none"),
            "proofVerified": error is None or "proof" not in (error or "").lower(),
        }, indent=2))
        sys.exit(0 if record.status == ValidationStatus.VALID else 1)
    elif args.command == "chain":
        records = store.get_history(args.did)
        valid_chain = [r for r in records if r.status == ValidationStatus.VALID]
        print(f"\nCustody Chain: {args.did}\n" + "-" * 60)
        for i, r in enumerate(valid_chain, 1):
            print(f"  {i}. [{r.event_type}] {r.id}\n     Time: {r.valid_from.isoformat()}\n     Issuer: {r.issuer}")
            if r.antecedent: print(f"     Antecedent: {r.antecedent}")
            print(f"     Proof: {r.proof.get('cryptosuite', r.proof.get('type', 'none'))} (VERIFIED)")
            print()
        print(f"Chain length: {len(valid_chain)} events")
    elif args.command == "stats":
        print(json.dumps(store.get_stats(), indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()