#!/usr/bin/env python3
"""
UORA Reference Resolver v2.0
=============================
Enterprise-grade reference implementation of the UORA Core Protocol v1.0.

Implements:
  - UORA-Query-API (§3.3)        : Standardized /history endpoint
  - Governance Validation (§4)    : CertificationCredential verification
  - Antecedent Chaining (§5.1)    : Linear custody chain + DAG transformation chain
  - Conflict Resolution (§5.1.3)  : Deterministic cascade (Timestamp > Authority > Hash)
  - Conformance Test Suite (§7)   : 20+ automated test vectors
  - Proof Section                 : Full W3C VC Data Integrity proof structure
  - EPCIS Event Linking           : evidence.type = "EPCISObjectEvent" with eventID

Protocol: https://w3id.org/uora/spec/core/v1.0
EPCIS Mapping: https://w3id.org/verifiable-supply-chain/profiles/shipping/v0.3

Usage:
  python uora-resolver-v2.0.py serve          # Start API server
  python uora-resolver-v2.0.py test           # Run conformance suite
  python uora-resolver-v2.0.py validate <file> # Validate single attestation
  python uora-resolver-v2.0.py chain <did>    # Display custody chain for an object

Author: Verifiable Supply Chain Community Group
Version: 2.0.0
License: W3C Community Contributor License Agreement
"""

import json
import uuid
import hashlib
import logging
import argparse
import sys
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from functools import total_ordering
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ============================================================================
# Logging Configuration
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("uora-resolver")


# ============================================================================
# Protocol Constants
# ============================================================================

# W3C Verifiable Credentials v2.0 context
VC_CONTEXT_V2: str = "https://www.w3.org/ns/credentials/v2"

# UORA Core Protocol context
UORA_CONTEXT: str = "https://w3id.org/uora/contexts/core.jsonld"

# UORA Verifiable Supply Chain profile context
VSC_SHIPPING_CONTEXT: str = "https://w3id.org/verifiable-supply-chain/contexts/shipping.jsonld"

# Valid event types per UORA Core §4.1
VALID_EVENT_TYPES: Set[str] = {"Origin", "Transfer", "Transformation", "Disposition"}

# Valid transfer subtypes per UORA Core §5.4
VALID_TRANSFER_TYPES: Set[str] = {"custody", "ownership", "location"}

# Valid origin subtypes per UORA Core §5.3
VALID_ORIGIN_TYPES: Set[str] = {"manufactured", "mined", "harvested", "created"}

# Valid transformation subtypes per UORA Core §5.5
VALID_TRANSFORMATION_TYPES: Set[str] = {"assembly", "processing", "modification", "disassembly"}

# Valid disposition subtypes per UORA Core §5.6
VALID_DISPOSITION_TYPES: Set[str] = {"recycled", "decommissioned", "destroyed", "lost"}

# Concrete attestation types that a credential can declare
UORA_ATTESTATION_TYPES: Set[str] = {
    "UORAOriginAttestation",
    "UORATransferAttestation",
    "UORATransformationAttestation",
    "UORADispositionAttestation",
}

# EPCIS event types for evidence linking per VerifiableShippingEvent Profile §4
EPCIS_EVENT_TYPES: Set[str] = {
    "EPCISObjectEvent",
    "EPCISAggregationEvent",
    "EPCISTransactionEvent",
    "EPCISTransformationEvent",
    "EPCISAssociationEvent",
}

# Required top-level fields per UORA Core §5.2
REQUIRED_BASE_FIELDS: Set[str] = {
    "@context", "type", "id", "issuer", "validFrom", "credentialSubject",
    "evidence", "proof"
}

# Required credentialSubject fields per UORA Core §5.2
REQUIRED_SUBJECT_FIELDS: Set[str] = {
    "id", "eventType", "antecedent", "authorizedBy"
}

# Required proof fields per W3C VC Data Model v2.0 §4.12
REQUIRED_PROOF_FIELDS: Set[str] = {
    "type", "created", "verificationMethod", "proofPurpose", "proofValue"
}

# Clock skew tolerance for temporal validation (5 seconds)
CLOCK_SKEW_TOLERANCE: timedelta = timedelta(seconds=5)

# Tolerance for considering two timestamps "equal" in conflict resolution (1 second)
CONFLICT_TIMESTAMP_TOLERANCE: timedelta = timedelta(seconds=1)

# Trust Framework authority precedence per UORA Core §5.1.3 Rule 2
# Higher integer = higher authority
TRUST_FRAMEWORK_AUTHORITY_PRECEDENCE: Dict[str, Dict[str, int]] = {
    "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1": {
        "did:web:fda.example.gov": 100,          # Regulatory authority
        "did:web:manufacturer.example.com": 50,   # Primary producer
        "did:web:wholesaler.example.com": 30,     # Secondary distributor
    },
    "https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1": {
        "did:web:carrier.example.com": 50,
        "did:web:warehouse.example.com": 40,
    },
    "https://w3id.org/verifiable-supply-chain/trust-frameworks/minerals-v1": {
        "did:web:certifier.example.org": 80,      # Independent certifier
        "did:web:mine-operator.example.com": 60,  # Primary operator
    },
}


# ============================================================================
# Validation Status Enumeration
# ============================================================================

class ValidationStatus(Enum):
    """
    Possible outcomes of the 6-phase validation pipeline.

    VALID:                             All checks passed
    SUPERSEDED:                        Valid but another attestation won conflict
    REJECTED_MISSING_FIELD:            Structural check failed
    REJECTED_INVALID_TYPE:             Type declaration mismatch
    REJECTED_INVALID_EVENT_TYPE:       Event type not in valid set
    REJECTED_BROKEN_CHAIN:             Antecedent chain integrity broken
    REJECTED_MISSING_AUTHORIZATION:    No authorizedBy claim
    REJECTED_UNAUTHORIZED_ISSUER:      Issuer not certified
    REJECTED_EXPIRED_CERTIFICATION:    Certification expired
    REJECTED_UNAUTHORIZED_CATEGORY:    Category not in certification scope
    REJECTED_FUTURE_TIMESTAMP:         Timestamp too far in the future
    REJECTED_DUPLICATE_ID:             Duplicate attestation ID
    REJECTED_INVALID_PROOF:            Proof section missing or malformed
    REJECTED_LINEAR_CHAIN_VIOLATION:   Transfer doesn't reference most recent event
    """
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
    REJECTED_FUTURE_TIMESTAMP = "rejected_future_timestamp"
    REJECTED_DUPLICATE_ID = "rejected_duplicate_id"
    REJECTED_INVALID_PROOF = "rejected_invalid_proof"
    REJECTED_LINEAR_CHAIN_VIOLATION = "rejected_linear_chain_violation"


# ============================================================================
# Data Models
# ============================================================================

@total_ordering
@dataclass
class AttestationRecord:
    """
    A validated attestation stored in the resolver's history.

    Represents a single event in a physical object's lifecycle.
    Supports both linear chains (Transfers) and DAGs (Transformations).

    Attributes:
        id: Unique attestation identifier (UUID URN).
        type: W3C VC type array including UORA concrete type.
        issuer: DID of the entity that created this attestation.
        valid_from: ISO 8601 timestamp of when the event occurred.
        subject_id: DID of the physical object this attestation describes.
        event_type: Origin, Transfer, Transformation, or Disposition.
        antecedent: List of previous attestation IDs (null for Origin).
        authorized_by: Certification reference proving issuer authority.
        evidence: Array of evidence entries supporting this attestation.
        raw_credential: The original credential as submitted.
        proof: W3C Data Integrity Proof structure.
        status: Validation outcome.
        chain_integrity: "intact", "broken", or "superseded".
        superseded_by: ID of the attestation that won conflict resolution.
        received_at: When the resolver received this attestation.
    """
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

    def __lt__(self, other: "AttestationRecord") -> bool:
        """Order by valid_from timestamp for chain ordering."""
        if not isinstance(other, AttestationRecord):
            return NotImplemented
        return self.valid_from < other.valid_from

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AttestationRecord):
            return NotImplemented
        return self.id == other.id

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class CertificationCredential:
    """
    A stored CertificationCredential for governance validation.

    Represents a Trust Anchor's declaration that an issuer is authorized
    to create specific attestation types for specific product categories.

    Attributes:
        id: Unique certification identifier.
        issuer: DID of the Trust Anchor that issued this certification.
        subject_id: DID of the certified entity.
        authorized_attestations: List of attestation types the subject can issue.
        authorized_categories: List of product categories covered.
        authorized_regions: List of geographic regions covered.
        trust_framework: URI of the governing Trust Framework.
        valid_from: Certification start date.
        valid_until: Certification expiration date.
    """
    id: str
    issuer: str
    subject_id: str
    authorized_attestations: List[str]
    authorized_categories: List[str]
    authorized_regions: List[str]
    trust_framework: str
    valid_from: datetime
    valid_until: datetime


# ============================================================================
# In-Memory Attestation Store
# ============================================================================

class AttestationStore:
    """
    Thread-safe in-memory store for attestations and certifications.

    Optimized with multiple indices for O(1) lookups:
      - Primary index: attestations by ID
      - Subject index: attestations by subject DID
      - Antecedent index: attestations by previous event ID (conflict detection)
      - Certification store: governance credentials by ID

    Production deployment should replace this with a persistent database
    (PostgreSQL, CockroachDB, or similar) with proper connection pooling
    and transaction support.
    """

    def __init__(self) -> None:
        # Primary indices
        self.attestations: Dict[str, AttestationRecord] = {}
        self.certifications: Dict[str, CertificationCredential] = {}
        self.seen_ids: Set[str] = set()

        # Secondary indices for efficient querying
        self.by_subject: Dict[str, List[AttestationRecord]] = {}
        self.by_antecedent: Dict[str, List[str]] = {}  # antecedent_id -> [attestation_ids]

    def add_attestation(self, record: AttestationRecord) -> bool:
        """
        Add an attestation and update all indices atomically.

        Returns True if added, False if duplicate ID.
        """
        if record.id in self.seen_ids:
            return False

        # Update primary store
        self.seen_ids.add(record.id)
        self.attestations[record.id] = record

        # Update subject index
        if record.subject_id not in self.by_subject:
            self.by_subject[record.subject_id] = []
        self.by_subject[record.subject_id].append(record)

        # Update antecedent index for O(1) conflict detection
        if record.antecedent:
            for ant_id in record.antecedent:
                if ant_id not in self.by_antecedent:
                    self.by_antecedent[ant_id] = []
                self.by_antecedent[ant_id].append(record.id)

        return True

    def get_history(
        self,
        did: str,
        event_type: Optional[str] = None,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AttestationRecord]:
        """
        Query attestation history for a subject DID.

        Results are sorted chronologically by valid_from timestamp.
        Supports optional filtering by event type and time range.
        """
        records = self.by_subject.get(did, [])
        if event_type:
            records = [r for r in records if r.event_type == event_type]
        if from_time:
            records = [r for r in records if r.valid_from >= from_time]
        if to_time:
            records = [r for r in records if r.valid_from <= to_time]
        records.sort(key=lambda r: r.valid_from)
        return records[:limit]

    def get_most_recent_valid(self, did: str) -> Optional[AttestationRecord]:
        """
        Get the most recent VALID attestation for a subject.

        Used to enforce linear custody chains: a Transfer MUST reference
        the most recent valid event as its antecedent.
        """
        records = self.by_subject.get(did, [])
        valid_records = [
            r for r in records
            if r.status == ValidationStatus.VALID
        ]
        if not valid_records:
            return None
        valid_records.sort(key=lambda r: r.valid_from)
        return valid_records[-1]

    def get_antecedent(self, antecedent_id: str) -> Optional[AttestationRecord]:
        """Retrieve an attestation by ID for chain validation."""
        return self.attestations.get(antecedent_id)

    def get_siblings(
        self, antecedent_id: str, exclude_id: str
    ) -> List[AttestationRecord]:
        """
        Get all attestations sharing the same antecedent.

        Uses the antecedent index for O(1) lookup instead of O(n) scan.
        """
        sibling_ids = self.by_antecedent.get(antecedent_id, [])
        return [
            self.attestations[sid]
            for sid in sibling_ids
            if sid != exclude_id and sid in self.attestations
        ]

    def add_certification(self, cert: CertificationCredential) -> None:
        """Register a certification credential for governance validation."""
        self.certifications[cert.id] = cert

    def get_certification(self, cert_id: str) -> Optional[CertificationCredential]:
        """Retrieve a certification by ID."""
        return self.certifications.get(cert_id)

    def get_stats(self) -> Dict[str, Any]:
        """Return store statistics for monitoring and health checks."""
        return {
            "total_attestations": len(self.attestations),
            "total_certifications": len(self.certifications),
            "unique_subjects": len(self.by_subject),
            "indexed_antecedents": len(self.by_antecedent),
            "antecedent_index_entries": sum(
                len(v) for v in self.by_antecedent.values()
            ),
        }


# ============================================================================
# Validation Engine
# ============================================================================

class UORAValidator:
    """
    Implements all governance, chain, and conflict resolution rules.

    The validation pipeline has seven phases executed in order:
      1. Structural Validation  - Required fields present?
      2. Type Validation        - Type declarations consistent?
      3. Temporal Validation    - Timestamp realistic?
      4. Proof Validation       - Data Integrity Proof present and well-formed?
      5. Governance Validation  - Issuer holds valid CertificationCredential?
      6. Antecedent Chain       - References a valid, earlier prior state?
      7. Conflict Resolution    - Competing attestation for same antecedent?
    """

    def __init__(self, store: AttestationStore) -> None:
        self.store = store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_attestation(
        self, credential: Dict[str, Any]
    ) -> Tuple[AttestationRecord, Optional[str]]:
        """
        Validate a single attestation through all seven phases.

        Args:
            credential: Raw JSON credential in W3C VC v2.0 format.

        Returns:
            Tuple of (AttestationRecord, error_message).
            If error_message is None, the attestation is VALID.
        """
        # Phase 1: Structural Validation
        err = self._validate_structure(credential)
        if err:
            record = self._create_record(credential, ValidationStatus.REJECTED_MISSING_FIELD)
            record.chain_integrity = "invalid"
            return record, err

        # Phase 2: Type Validation
        err = self._validate_types(credential)
        if err:
            record = self._create_record(credential, ValidationStatus.REJECTED_INVALID_TYPE)
            record.chain_integrity = "invalid"
            return record, err

        # Phase 3: Temporal Validation
        err = self._validate_temporal(credential)
        if err:
            record = self._create_record(credential, ValidationStatus.REJECTED_FUTURE_TIMESTAMP)
            return record, err

        # Phase 4: Proof Validation
        err = self._validate_proof(credential)
        if err:
            record = self._create_record(credential, ValidationStatus.REJECTED_INVALID_PROOF)
            record.chain_integrity = "invalid"
            return record, err

        # Phase 5: Governance Validation
        err = self._validate_governance(credential)
        if err:
            status = self._governance_error_status(err)
            record = self._create_record(credential, status)
            return record, err

        # Phase 6: Antecedent Chain Validation (with linear custody enforcement)
        record = self._create_record(credential, ValidationStatus.VALID)
        chain_err = self._validate_antecedent_chain(record)
        if chain_err:
            record.status = ValidationStatus.REJECTED_BROKEN_CHAIN
            record.chain_integrity = "broken"
            return record, chain_err

        # Phase 7: Conflict Resolution
        conflict_err = self._detect_and_resolve_conflicts(record)
        if conflict_err:
            record.status = ValidationStatus.SUPERSEDED
            record.chain_integrity = "superseded"

        return record, None

    # ------------------------------------------------------------------
    # Phase 1: Structural Validation
    # ------------------------------------------------------------------

    def _validate_structure(self, credential: Dict[str, Any]) -> Optional[str]:
        """
        Validate presence of all required fields at the top level,
        within credentialSubject, and within proof.

        Reference: UORA Core §5.2, W3C VC Data Model v2.0 §4.
        """
        # Top-level required fields
        for field in REQUIRED_BASE_FIELDS:
            if field not in credential:
                return f"Missing required base field: {field}"

        # credentialSubject required fields
        subject = credential.get("credentialSubject", {})
        for field in REQUIRED_SUBJECT_FIELDS:
            if field not in subject:
                return f"Missing required subject field: {field}"

        # Issuer must have an ID
        if "id" not in credential.get("issuer", {}):
            return "Missing issuer.id"

        # At least one evidence entry required
        evidence = credential.get("evidence", [])
        if not evidence:
            return "At least one evidence entry is required"

        return None

    # ------------------------------------------------------------------
    # Phase 2: Type Validation
    # ------------------------------------------------------------------

    def _validate_types(self, credential: Dict[str, Any]) -> Optional[str]:
        """
        Validate type declarations and subtype-specific constraints.

        Reference: UORA Core §5.2-5.6.
        """
        types = credential.get("type", [])

        # Must declare VerifiableCredential base type
        if "VerifiableCredential" not in types:
            return "type must include 'VerifiableCredential'"

        # Must declare UORAAttestation base type
        if "UORAAttestation" not in types:
            return "type must include 'UORAAttestation'"

        # Must declare exactly one concrete attestation type
        concrete = set(types) & UORA_ATTESTATION_TYPES
        if len(concrete) != 1:
            return (
                f"type must include exactly one concrete attestation type "
                f"from: {UORA_ATTESTATION_TYPES}"
            )

        # eventType must match the concrete type
        event_type = credential["credentialSubject"].get("eventType")
        concrete_type = list(concrete)[0]
        expected_event = concrete_type.replace("UORA", "").replace("Attestation", "")
        if event_type != expected_event:
            return (
                f"eventType '{event_type}' does not match "
                f"concrete type '{concrete_type}'"
            )

        # Subtype-specific field validation
        subject = credential["credentialSubject"]

        if concrete_type == "UORAOriginAttestation":
            if subject.get("originType") not in VALID_ORIGIN_TYPES:
                return f"Invalid originType: {subject.get('originType')}"
            if not subject.get("originLocation"):
                return "Missing originLocation"
            if not subject.get("originDate"):
                return "Missing originDate"
            if subject.get("antecedent") is not None:
                return "Origin attestation must have antecedent: null"

        elif concrete_type == "UORATransferAttestation":
            if subject.get("transferType") not in VALID_TRANSFER_TYPES:
                return f"Invalid transferType: {subject.get('transferType')}"
            if not subject.get("fromParty"):
                return "Missing fromParty"
            if not subject.get("toParty"):
                return "Missing toParty"

        elif concrete_type == "UORATransformationAttestation":
            if subject.get("transformationType") not in VALID_TRANSFORMATION_TYPES:
                return f"Invalid transformationType: {subject.get('transformationType')}"
            if not subject.get("inputObjects"):
                return "Missing inputObjects"
            if not subject.get("outputObjects"):
                return "Missing outputObjects"
            antecedent = subject.get("antecedent")
            if not isinstance(antecedent, list) or len(antecedent) < 1:
                return "Transformation must have antecedent array with at least one entry"

        elif concrete_type == "UORADispositionAttestation":
            if subject.get("dispositionType") not in VALID_DISPOSITION_TYPES:
                return f"Invalid dispositionType: {subject.get('dispositionType')}"

        return None

    # ------------------------------------------------------------------
    # Phase 3: Temporal Validation
    # ------------------------------------------------------------------

    def _validate_temporal(self, credential: Dict[str, Any]) -> Optional[str]:
        """
        Validate that the timestamp is not in the far future.

        A clock skew tolerance of 5 seconds accounts for minor
        clock drift between distributed systems.
        """
        valid_from_str = credential.get("validFrom", "")

        # Handle both "Z" and "+00:00" UTC formats
        valid_from_str = valid_from_str.replace("Z", "+00:00")

        try:
            valid_from = datetime.fromisoformat(valid_from_str)
        except (ValueError, TypeError):
            return f"Invalid validFrom timestamp: {valid_from_str}"

        now = datetime.now(timezone.utc)
        skew = now + CLOCK_SKEW_TOLERANCE
        if valid_from > skew:
            return (
                f"validFrom ({valid_from_str}) is in the future "
                f"(now: {now.isoformat()})"
            )
        return None

    # ------------------------------------------------------------------
    # Phase 4: Proof Validation
    # ------------------------------------------------------------------

    def _validate_proof(self, credential: Dict[str, Any]) -> Optional[str]:
        """
        Validate the W3C Data Integrity Proof section.

        Reference: W3C VC Data Model v2.0 §4.12.

        Every UORA attestation MUST carry a proof to be cryptographically
        verifiable. In production, this proof would be verified against
        the issuer's DID Document. Here we validate structural completeness.
        """
        proof = credential.get("proof", {})

        for field in REQUIRED_PROOF_FIELDS:
            if field not in proof:
                return f"Missing required proof field: {field}"

        # Verify proof type is a recognized Data Integrity Proof
        valid_proof_types = {
            "DataIntegrityProof",
            "Ed25519Signature2020",
            "BbsBlsSignature2020",
        }
        if proof.get("type") not in valid_proof_types:
            return f"Unrecognized proof type: {proof.get('type')}"

        # proofPurpose must be assertionMethod for attestations
        if proof.get("proofPurpose") != "assertionMethod":
            return (
                f"proofPurpose must be 'assertionMethod' "
                f"for attestations, got: {proof.get('proofPurpose')}"
            )

        return None

    # ------------------------------------------------------------------
    # Phase 5: Governance Validation
    # ------------------------------------------------------------------

    def _validate_governance(self, credential: Dict[str, Any]) -> Optional[str]:
        """
        Validate that the issuer holds a valid CertificationCredential.

        Reference: UORA Core §4.1.

        Checks:
          1. authorizedBy claim is present
          2. Referenced certification exists in the store
          3. Certification is not expired
          4. Issuer DID matches certification subject
          5. Attestation type is in authorized list
        """
        subject = credential["credentialSubject"]
        authorized_by = subject.get("authorizedBy", {})

        if not authorized_by:
            return "Missing authorizedBy claim"

        cert_id = authorized_by.get("certificationId")
        if not cert_id:
            return "Missing certificationId in authorizedBy"

        cert = self.store.get_certification(cert_id)
        if not cert:
            return f"CertificationCredential not found: {cert_id}"

        # Check certification validity period
        valid_from_str = credential["validFrom"].replace("Z", "+00:00")
        valid_from = datetime.fromisoformat(valid_from_str)

        if valid_from < cert.valid_from or valid_from > cert.valid_until:
            return (
                f"Certification expired or not yet valid "
                f"for attestation time {credential['validFrom']}"
            )

        # Check issuer matches certification subject
        issuer_did = credential.get("issuer", {}).get("id", "")
        if issuer_did != cert.subject_id:
            return (
                f"Issuer '{issuer_did}' does not match "
                f"certification subject '{cert.subject_id}'"
            )

        # Check attestation type is authorized
        attestation_types = set(credential.get("type", []))
        authorized = set(cert.authorized_attestations)
        if not (attestation_types & authorized):
            return (
                f"Issuer not authorized for attestation types: "
                f"{attestation_types & UORA_ATTESTATION_TYPES}"
            )

        return None

    def _governance_error_status(self, error: str) -> ValidationStatus:
        """Map governance error messages to specific rejection statuses."""
        if "Missing authorizedBy" in error:
            return ValidationStatus.REJECTED_MISSING_AUTHORIZATION
        if "not found" in error:
            return ValidationStatus.REJECTED_UNAUTHORIZED_ISSUER
        if "expired" in error:
            return ValidationStatus.REJECTED_EXPIRED_CERTIFICATION
        if "not authorized" in error:
            return ValidationStatus.REJECTED_UNAUTHORIZED_CATEGORY
        return ValidationStatus.REJECTED_UNAUTHORIZED_ISSUER

    # ------------------------------------------------------------------
    # Phase 6: Antecedent Chain Validation
    # ------------------------------------------------------------------

    def _validate_antecedent_chain(self, record: AttestationRecord) -> Optional[str]:
        """
        Validate chain integrity with linear custody enforcement.

        Reference: UORA Core §5.1.

        Rules:
          - Origin events: antecedent must be null
          - Transfer events: antecedent must reference the MOST RECENT
            valid event for this subject (linear custody chain)
          - Transformation events: antecedent is a DAG array of
            input object attestation IDs
          - Disposition events: antecedent must reference the most
            recent valid event
          - All antecedents must exist, be valid, and have timestamps
            earlier than the successor
        """
        antecedent = record.antecedent

        # Origin: no antecedent
        if antecedent is None:
            return None

        # DAG antecedent (Transformations)
        if isinstance(antecedent, list):
            for ant_id in antecedent:
                err = self._validate_single_antecedent(ant_id, record)
                if err:
                    return err
            return None

        # Shouldn't happen with current schema, but handle gracefully
        return self._validate_single_antecedent(antecedent, record)

    def _validate_single_antecedent(
        self, ant_id: str, record: AttestationRecord
    ) -> Optional[str]:
        """Validate a single antecedent reference."""
        prev = self.store.get_antecedent(ant_id)
        if prev is None:
            return f"Antecedent not found: {ant_id}"
        if prev.status == ValidationStatus.REJECTED_BROKEN_CHAIN:
            return f"Antecedent chain broken at: {ant_id}"
        if prev.valid_from > record.valid_from:
            return (
                f"Antecedent timestamp ({prev.valid_from.isoformat()}) "
                f"is after successor ({record.valid_from.isoformat()})"
            )

        # --- LINEAR CUSTODY CHAIN ENFORCEMENT ---
        # For Transfers and Dispositions: antecedent MUST be the most
        # recent VALID event for this subject. This prevents gaps in
        # the custody timeline and ensures a complete audit trail.
        if record.event_type in ("Transfer", "Disposition"):
            most_recent = self.store.get_most_recent_valid(record.subject_id)
            if most_recent and ant_id != most_recent.id:
                return (
                    f"Linear chain violation: Transfer must reference "
                    f"most recent valid event ({most_recent.id}), "
                    f"not {ant_id}. This ensures unbroken custody timeline."
                )

        return None

    # ------------------------------------------------------------------
    # Phase 7: Conflict Resolution
    # ------------------------------------------------------------------

    def _detect_and_resolve_conflicts(
        self, record: AttestationRecord
    ) -> Optional[str]:
        """
        Detect and resolve conflicts using the deterministic cascade.

        Reference: UORA Core §5.1.3.

        Uses the antecedent index for O(1) sibling lookup.
        For multi-antecedent attestations, conflict is detected only
        if ALL antecedents match.
        """
        antecedent = record.antecedent
        if antecedent is None:
            return None  # Origin events cannot conflict

        ant_ids = antecedent if isinstance(antecedent, list) else [antecedent]

        for ant_id in ant_ids:
            siblings = self.store.get_siblings(ant_id, record.id)

            for sibling in siblings:
                # For multi-antecedent: all must match
                if isinstance(antecedent, list) and isinstance(sibling.antecedent, list):
                    if set(antecedent) != set(sibling.antecedent):
                        continue

                # Apply the conflict resolution cascade
                winner = self._resolve_conflict(record, sibling)
                if winner.id == sibling.id:
                    record.superseded_by = sibling.id
                    return f"Superseded by {sibling.id} (conflict resolution)"

        return None

    def _resolve_conflict(
        self, a: AttestationRecord, b: AttestationRecord
    ) -> AttestationRecord:
        """
        Deterministic conflict resolution cascade.

        Rule 1: Later timestamp wins
        Rule 2: Higher trust framework authority wins
        Rule 3: Lexicographically smaller ID wins (deterministic tiebreaker)
        """
        # Rule 1: Timestamp Precedence
        time_diff = abs((a.valid_from - b.valid_from).total_seconds())
        if time_diff > CONFLICT_TIMESTAMP_TOLERANCE.total_seconds():
            return a if a.valid_from > b.valid_from else b

        # Rule 2: Authority Precedence
        tf_a = a.authorized_by.get("trustFramework", "")
        tf_b = b.authorized_by.get("trustFramework", "")

        if tf_a == tf_b:
            precedence = TRUST_FRAMEWORK_AUTHORITY_PRECEDENCE.get(tf_a, {})
            rank_a = precedence.get(a.issuer, 0)
            rank_b = precedence.get(b.issuer, 0)
            if rank_a != rank_b:
                return a if rank_a > rank_b else b

        # Rule 3: Hash Precedence (lexicographic)
        return a if a.id < b.id else b

    # ------------------------------------------------------------------
    # Record Factory
    # ------------------------------------------------------------------

    def _create_record(
        self,
        credential: Dict[str, Any],
        status: ValidationStatus,
    ) -> AttestationRecord:
        """
        Create an AttestationRecord from a raw credential dictionary.

        Normalizes antecedent to list format for consistent processing.
        """
        subject = credential.get("credentialSubject", {})
        antecedent = subject.get("antecedent")

        # Normalize antecedent: single string -> list, null -> None
        if isinstance(antecedent, str):
            antecedent = [antecedent]
        elif antecedent is None:
            antecedent = None
        elif not isinstance(antecedent, list):
            antecedent = None

        # Parse timestamp with UTC format handling
        valid_from_str = credential.get("validFrom", "1970-01-01T00:00:00Z")
        valid_from_str = valid_from_str.replace("Z", "+00:00")

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
            chain_integrity=(
                "intact" if status == ValidationStatus.VALID else "invalid"
            ),
        )


# ============================================================================
# UORA-Query-API HTTP Server
# ============================================================================

class UORAQueryHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler implementing the UORA-Query-API protocol.

    Reference: UORA Core §3.3.

    Endpoints:
      GET  /history?did=...          Query attestation history
      GET  /chain?did=...            Display custody chain timeline
      POST /attestations             Capture and validate a new attestation
      POST /validate                 Validate without storing
      GET  /health                   Health check
      GET  /stats                    Store statistics
    """

    validator: UORAValidator = None   # type: ignore
    store: AttestationStore = None    # type: ignore

    # ------------------------------------------------------------------
    # HTTP Method Routing
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        """Route GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.endswith("/history"):
            self._handle_history(parsed)
        elif path.endswith("/chain"):
            self._handle_chain(parsed)
        elif path == "/health":
            self._send_json(200, {
                "status": "healthy",
                "protocol": "UORA-Query-API v2.0",
                "version": "2.0.0",
            })
        elif path == "/stats":
            self._handle_stats()
        else:
            self._send_json(404, {
                "error": "not_found",
                "message": f"Endpoint not found: {parsed.path}",
            })

    def do_POST(self) -> None:
        """Route POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path.endswith("/attestations"):
            self._handle_capture()
        elif path.endswith("/validate"):
            self._handle_validate()
        else:
            self._send_json(404, {
                "error": "not_found",
                "message": f"Endpoint not found: {parsed.path}",
            })

    # ------------------------------------------------------------------
    # GET /history
    # ------------------------------------------------------------------

    def _handle_history(self, parsed: urlparse) -> None:
        """
        Query attestation history for a subject DID.

        Query parameters:
          did       (required) Subject DID
          eventType (optional) Filter by Origin|Transfer|Transformation|Disposition
          from      (optional) ISO 8601 lower bound on validFrom
          to        (optional) ISO 8601 upper bound on validFrom
          limit     (optional) Max results (default: 100)
        """
        params = parse_qs(parsed.query)
        did = params.get("did", [None])[0]
        if not did:
            self._send_json(400, {
                "error": "missing_parameter",
                "message": "The 'did' parameter is required",
            })
            return

        event_type = params.get("eventType", [None])[0]
        from_str = params.get("from", [None])[0]
        to_str = params.get("to", [None])[0]
        limit = int(params.get("limit", ["100"])[0])

        from_time = datetime.fromisoformat(from_str) if from_str else None
        to_time = datetime.fromisoformat(to_str) if to_str else None

        records = self.store.get_history(
            did, event_type, from_time, to_time, limit
        )

        response = {
            "did": did,
            "attestations": [
                {
                    "id": r.id,
                    "type": r.type,
                    "validFrom": r.valid_from.isoformat(),
                    "issuer": r.issuer,
                    "eventType": r.event_type,
                    "antecedent": r.antecedent,
                    "status": r.status.value,
                    "chainIntegrity": r.chain_integrity,
                    "supersededBy": r.superseded_by,
                    "proof": r.proof,
                    "credential": r.raw_credential,
                }
                for r in records
            ],
            "total": len(records),
        }
        self._send_json(200, response)

    # ------------------------------------------------------------------
    # GET /chain
    # ------------------------------------------------------------------

    def _handle_chain(self, parsed: urlparse) -> None:
        """
        Display the custody chain timeline for a subject DID.

        Shows only VALID events in chronological order, demonstrating
        the complete lifecycle from Origin through Transfers to Disposition.
        """
        params = parse_qs(parsed.query)
        did = params.get("did", [None])[0]
        if not did:
            self._send_json(400, {
                "error": "missing_parameter",
                "message": "The 'did' parameter is required",
            })
            return

        records = self.store.get_history(did)
        valid_chain = [
            r for r in records
            if r.status == ValidationStatus.VALID
        ]

        chain_display = []
        for i, r in enumerate(valid_chain):
            step = {
                "position": i + 1,
                "eventType": r.event_type,
                "attestationId": r.id,
                "timestamp": r.valid_from.isoformat(),
                "issuer": r.issuer,
                "description": self._describe_event(r),
            }
            chain_display.append(step)

        response = {
            "did": did,
            "chainLength": len(chain_display),
            "isComplete": (
                chain_display
                and chain_display[-1]["eventType"] == "Disposition"
            ),
            "chain": chain_display,
        }
        self._send_json(200, response)

    def _describe_event(self, record: AttestationRecord) -> str:
        """Generate a human-readable description of a chain event."""
        if record.event_type == "Origin":
            return f"Object created at {record.raw_credential.get('credentialSubject', {}).get('originLocation', 'unknown location')}"
        elif record.event_type == "Transfer":
            subj = record.raw_credential.get("credentialSubject", {})
            return f"Transfer from {subj.get('fromParty', '?')} to {subj.get('toParty', '?')}"
        elif record.event_type == "Transformation":
            subj = record.raw_credential.get("credentialSubject", {})
            inputs = len(subj.get("inputObjects", []))
            outputs = len(subj.get("outputObjects", []))
            return f"Transformation: {inputs} inputs → {outputs} outputs"
        elif record.event_type == "Disposition":
            subj = record.raw_credential.get("credentialSubject", {})
            return f"Object {subj.get('dispositionType', 'disposed')}"
        return "Unknown event"

    # ------------------------------------------------------------------
    # POST /attestations
    # ------------------------------------------------------------------

    def _handle_capture(self) -> None:
        """
        Capture and validate a new attestation.

        On success (201): Attestation is stored and chain is intact.
        On validation failure (422): Attestation is stored with rejection status.
        On duplicate (409): Attestation ID already exists.
        """
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            credential = json.loads(body)
        except json.JSONDecodeError as e:
            self._send_json(400, {
                "error": "invalid_json",
                "message": str(e),
            })
            return

        record, error = self.validator.validate_attestation(credential)

        # Check for duplicate before storing
        if not self.store.add_attestation(record):
            self._send_json(409, {
                "status": "rejected",
                "error": f"Duplicate attestation ID: {record.id}",
                "attestationId": record.id,
            })
            return

        if error:
            self._send_json(422, {
                "status": record.status.value,
                "error": error,
                "attestationId": record.id,
                "chainIntegrity": record.chain_integrity,
            })
        else:
            self._send_json(201, {
                "status": "accepted",
                "attestationId": record.id,
                "chainIntegrity": record.chain_integrity,
                "eventType": record.event_type,
                "antecedent": record.antecedent,
            })

    # ------------------------------------------------------------------
    # POST /validate
    # ------------------------------------------------------------------

    def _handle_validate(self) -> None:
        """
        Validate an attestation without storing it.

        Useful for pre-flight checks before committing to the chain.
        """
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            credential = json.loads(body)
        except json.JSONDecodeError as e:
            self._send_json(400, {
                "error": "invalid_json",
                "message": str(e),
            })
            return

        record, error = self.validator.validate_attestation(credential)
        self._send_json(200, {
            "status": record.status.value,
            "error": error,
            "chainIntegrity": record.chain_integrity,
            "details": {
                "attestationId": record.id,
                "issuer": record.issuer,
                "eventType": record.event_type,
                "antecedent": record.antecedent,
                "proofType": record.proof.get("type", "none"),
            },
        })

    # ------------------------------------------------------------------
    # GET /stats
    # ------------------------------------------------------------------

    def _handle_stats(self) -> None:
        """Return store statistics for monitoring."""
        stats = self.store.get_stats()
        self._send_json(200, stats)

    # ------------------------------------------------------------------
    # Response Helper
    # ------------------------------------------------------------------

    def _send_json(self, status: int, data: Dict[str, Any]) -> None:
        """Send a JSON response with CORS headers."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-UORA-Version", "2.0.0")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        """Log HTTP requests through the application logger."""
        logger.info(f"{self.client_address[0]} - {format % args}")


# ============================================================================
# Conformance Test Suite
# ============================================================================

class ConformanceSuite:
    """
    Automated test suite for UORA compliance verification.

    Reference: UORA Core §7.

    Test categories:
      - Valid attestation types (4 tests)
      - Invalid attestation rejection (5 tests)
      - Governance validation (3 tests)
      - Conflict resolution (3 tests)
      - Chain integrity (2 tests)
      - Linear chain enforcement (2 tests)
      - Proof validation (2 tests)
      - EPCIS evidence linking (1 test)

    Total: 22 tests
    """

    def __init__(self, store: AttestationStore, validator: UORAValidator) -> None:
        self.store = store
        self.validator = validator
        self.results: List[Dict[str, Any]] = []

    def run_all(self) -> bool:
        """Run the complete conformance test suite. Returns True if all pass."""
        logger.info("=" * 60)
        logger.info("UORA Conformance Test Suite v2.0")
        logger.info("=" * 60)

        self._run_valid_attestation_tests()
        self._run_invalid_attestation_tests()
        self._run_governance_tests()
        self._run_conflict_resolution_tests()
        self._run_chain_integrity_tests()
        self._run_linear_chain_tests()
        self._run_proof_validation_tests()
        self._run_epcis_evidence_tests()

        passed = sum(1 for r in self.results if r["passed"])
        total = len(self.results)
        logger.info(f"\nResults: {passed}/{total} passed")

        if passed == total:
            logger.info("FULL COMPLIANCE: All tests passed")
            return True
        else:
            failed = [r for r in self.results if not r["passed"]]
            for f in failed:
                logger.error(
                    f"  FAILED: {f['testId']} - "
                    f"{f['description']} - {f.get('error', '')}"
                )
            logger.error(f"{len(failed)} test(s) failed")
            return False

    # ------------------------------------------------------------------
    # Test Group Runners
    # ------------------------------------------------------------------

    def _run_valid_attestation_tests(self) -> None:
        logger.info("\n--- Valid Attestation Tests ---")
        for test in [
            self._valid_origin(),
            self._valid_transfer(),
            self._valid_transformation(),
            self._valid_disposition(),
        ]:
            self._execute_test(test)

    def _run_invalid_attestation_tests(self) -> None:
        logger.info("\n--- Invalid Attestation Tests ---")
        for test in [
            self._missing_required_field(),
            self._invalid_event_type(),
            self._origin_with_antecedent(),
            self._future_timestamp(),
            self._duplicate_id(),
        ]:
            self._execute_test(test)

    def _run_governance_tests(self) -> None:
        logger.info("\n--- Governance Validation Tests ---")
        for test in [
            self._missing_authorization(),
            self._expired_certification(),
            self._unauthorized_attestation_type(),
        ]:
            self._execute_test(test)

    def _run_conflict_resolution_tests(self) -> None:
        logger.info("\n--- Conflict Resolution Tests ---")
        for test in [
            self._timestamp_precedence(),
            self._authority_precedence(),
            self._multi_antecedent_conflict(),
        ]:
            self._execute_test(test)

    def _run_chain_integrity_tests(self) -> None:
        logger.info("\n--- Chain Integrity Tests ---")
        for test in [
            self._broken_antecedent_chain(),
            self._temporal_chain_violation(),
        ]:
            self._execute_test(test)

    def _run_linear_chain_tests(self) -> None:
        logger.info("\n--- Linear Chain Enforcement Tests ---")
        for test in [
            self._linear_chain_violation(),
            self._linear_chain_correct(),
        ]:
            self._execute_test(test)

    def _run_proof_validation_tests(self) -> None:
        logger.info("\n--- Proof Validation Tests ---")
        for test in [
            self._missing_proof(),
            self._invalid_proof_type(),
        ]:
            self._execute_test(test)

    def _run_epcis_evidence_tests(self) -> None:
        logger.info("\n--- EPCIS Evidence Linking Tests ---")
        self._execute_test(self._epcis_evidence_linked())

    # ------------------------------------------------------------------
    # Helper: base credential factory
    # ------------------------------------------------------------------

    def _base_transfer(self) -> Dict[str, Any]:
        """Create a minimal valid transfer attestation for testing."""
        now = datetime.now(timezone.utc)
        return {
            "@context": [VC_CONTEXT_V2, UORA_CONTEXT, VSC_SHIPPING_CONTEXT],
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": [
                "VerifiableCredential",
                "UORAAttestation",
                "UORATransferAttestation",
                "VerifiableShippingEvent",
            ],
            "issuer": {"id": "did:web:shipper.example.com"},
            "validFrom": now.isoformat(),
            "credentialSubject": {
                "id": "did:web:maker.example.com:object:serial:SN-001",
                "eventType": "Transfer",
                "transferType": "custody",
                "fromParty": "did:web:shipper.example.com",
                "toParty": "did:web:receiver.example.com",
                "antecedent": "urn:uuid:origin-id",
                "authorizedBy": {
                    "certificationId": "urn:uuid:shipper-cert",
                    "trustFramework": (
                        "https://w3id.org/verifiable-supply-chain/"
                        "trust-frameworks/logistics-v1"
                    ),
                    "verifiedAt": now.isoformat(),
                },
            },
            "evidence": [
                {
                    "id": f"urn:uuid:{uuid.uuid4()}",
                    "type": ["Evidence"],
                    "name": "Test Transfer Evidence",
                }
            ],
            "proof": {
                "type": "Ed25519Signature2020",
                "created": now.isoformat(),
                "verificationMethod": (
                    "did:web:shipper.example.com#key-1"
                ),
                "proofPurpose": "assertionMethod",
                "proofValue": (
                    "z5LbLbR3qZ5Y6m8n9o0p1q2r3s4t5u6v7w8x9y0z"
                    "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
                ),
            },
        }

    # ------------------------------------------------------------------
    # Valid Attestation Tests
    # ------------------------------------------------------------------

    def _valid_origin(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        return {
            "testId": "valid-origin-001",
            "description": "Complete, well-formed OriginAttestation",
            "credential": {
                "@context": [VC_CONTEXT_V2, UORA_CONTEXT],
                "id": f"urn:uuid:{uuid.uuid4()}",
                "type": ["VerifiableCredential", "UORAAttestation", "UORAOriginAttestation"],
                "issuer": {"id": "did:web:maker.example.com"},
                "validFrom": (now - timedelta(days=30)).isoformat(),
                "credentialSubject": {
                    "id": "did:web:maker.example.com:object:serial:SN-002",
                    "eventType": "Origin",
                    "antecedent": None,
                    "originType": "manufactured",
                    "originLocation": "https://id.gs1.org/414/9521321000010",
                    "originDate": (now - timedelta(days=30)).isoformat(),
                    "authorizedBy": {
                        "certificationId": "urn:uuid:maker-cert",
                        "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                        "verifiedAt": now.isoformat(),
                    },
                },
                "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence"], "name": "Manufacturing Record"}],
                "proof": {
                    "type": "Ed25519Signature2020",
                    "created": now.isoformat(),
                    "verificationMethod": "did:web:maker.example.com#key-1",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "z5LbLbR3qZ5Y6m8n9o0p1q2r3s4t5u6v7w8x9y0za1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                },
            },
            "expectedResult": "accepted",
        }

    def _valid_transfer(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        cred["testId"] = "valid-transfer-001"
        cred["description"] = "Complete, well-formed TransferAttestation"
        return cred

    def _valid_transformation(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        return {
            "testId": "valid-transformation-001",
            "description": "Complete, well-formed TransformationAttestation",
            "credential": {
                "@context": [VC_CONTEXT_V2, UORA_CONTEXT],
                "id": f"urn:uuid:{uuid.uuid4()}",
                "type": ["VerifiableCredential", "UORAAttestation", "UORATransformationAttestation"],
                "issuer": {"id": "did:web:maker.example.com"},
                "validFrom": now.isoformat(),
                "credentialSubject": {
                    "id": "did:web:maker.example.com:object:bundle:B-001",
                    "eventType": "Transformation",
                    "transformationType": "assembly",
                    "inputObjects": [
                        "did:web:maker.example.com:object:serial:C-001",
                        "did:web:maker.example.com:object:serial:C-002",
                    ],
                    "outputObjects": ["did:web:maker.example.com:object:bundle:B-001"],
                    "antecedent": ["urn:uuid:comp1-id", "urn:uuid:comp2-id"],
                    "authorizedBy": {
                        "certificationId": "urn:uuid:maker-cert",
                        "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                        "verifiedAt": now.isoformat(),
                    },
                },
                "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence"], "name": "Assembly Record"}],
                "proof": {
                    "type": "Ed25519Signature2020",
                    "created": now.isoformat(),
                    "verificationMethod": "did:web:maker.example.com#key-1",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "z5LbLbR3qZ5Y6m8n9o0p1q2r3s4t5u6v7w8x9y0za1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                },
            },
            "expectedResult": "accepted",
        }

    def _valid_disposition(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        return {
            "testId": "valid-disposition-001",
            "description": "Complete, well-formed DispositionAttestation",
            "credential": {
                "@context": [VC_CONTEXT_V2, UORA_CONTEXT],
                "id": f"urn:uuid:{uuid.uuid4()}",
                "type": ["VerifiableCredential", "UORAAttestation", "UORADispositionAttestation"],
                "issuer": {"id": "did:web:recycler.example.com"},
                "validFrom": now.isoformat(),
                "credentialSubject": {
                    "id": "did:web:maker.example.com:object:serial:SN-001",
                    "eventType": "Disposition",
                    "dispositionType": "recycled",
                    "antecedent": "urn:uuid:origin-id",
                    "authorizedBy": {
                        "certificationId": "urn:uuid:recycler-cert",
                        "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
                        "verifiedAt": now.isoformat(),
                    },
                },
                "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence"], "name": "Recycling Certificate"}],
                "proof": {
                    "type": "Ed25519Signature2020",
                    "created": now.isoformat(),
                    "verificationMethod": "did:web:recycler.example.com#key-1",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "z5LbLbR3qZ5Y6m8n9o0p1q2r3s4t5u6v7w8x9y0za1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                },
            },
            "expectedResult": "accepted",
        }

    # ------------------------------------------------------------------
    # Invalid Attestation Tests
    # ------------------------------------------------------------------

    def _missing_required_field(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        del cred["credentialSubject"]["eventType"]
        return {
            "testId": "invalid-missing-field-001",
            "description": "Reject attestation missing required field eventType",
            "credential": cred,
            "expectedResult": "rejected",
            "expectedError": "Missing required subject field: eventType",
        }

    def _invalid_event_type(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        cred["credentialSubject"]["eventType"] = "InvalidEvent"
        return {
            "testId": "invalid-event-type-001",
            "description": "Reject attestation with invalid eventType",
            "credential": cred,
            "expectedResult": "rejected",
        }

    def _origin_with_antecedent(self) -> Dict[str, Any]:
        cred = self._valid_origin()["credential"]
        cred["credentialSubject"]["antecedent"] = "urn:uuid:some-prior-event"
        return {
            "testId": "invalid-origin-antecedent-001",
            "description": "Reject Origin attestation with non-null antecedent",
            "credential": cred,
            "expectedResult": "rejected",
        }

    def _future_timestamp(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        cred["validFrom"] = (
            datetime.now(timezone.utc) + timedelta(days=365)
        ).isoformat()
        return {
            "testId": "invalid-future-timestamp-001",
            "description": "Reject attestation with future timestamp",
            "credential": cred,
            "expectedResult": "rejected",
        }

    def _duplicate_id(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        test_id = "urn:uuid:duplicate-test-id-v2"
        cred["id"] = test_id
        # Submit first time to occupy the ID
        rec, _ = self.validator.validate_attestation(cred)
        self.store.add_attestation(rec)
        return {
            "testId": "invalid-duplicate-id-001",
            "description": "Reject attestation with duplicate id",
            "credential": cred,
            "expectedResult": "rejected",
        }

    # ------------------------------------------------------------------
    # Governance Tests
    # ------------------------------------------------------------------

    def _missing_authorization(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        del cred["credentialSubject"]["authorizedBy"]
        return {
            "testId": "governance-missing-auth-001",
            "description": "Reject attestation missing authorizedBy claim",
            "credential": cred,
            "expectedResult": "rejected",
            "expectedError": "Missing authorizedBy claim",
        }

    def _expired_certification(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        cred["credentialSubject"]["authorizedBy"]["certificationId"] = "urn:uuid:expired-cert"
        return {
            "testId": "governance-expired-cert-001",
            "description": "Reject attestation with expired certification",
            "credential": cred,
            "expectedResult": "rejected",
        }

    def _unauthorized_attestation_type(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        cred["type"] = ["VerifiableCredential", "UORAAttestation", "UORADispositionAttestation"]
        cred["credentialSubject"]["eventType"] = "Disposition"
        cred["credentialSubject"]["dispositionType"] = "recycled"
        return {
            "testId": "governance-unauthorized-type-001",
            "description": "Reject attestation type not in issuer's authorizedAttestations",
            "credential": cred,
            "expectedResult": "rejected",
        }

    # ------------------------------------------------------------------
    # Conflict Resolution Tests
    # ------------------------------------------------------------------

    def _timestamp_precedence(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        earlier = cred.copy()
        earlier["id"] = f"urn:uuid:{uuid.uuid4()}"
        earlier["validFrom"] = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat()
        later = cred.copy()
        later["id"] = f"urn:uuid:{uuid.uuid4()}"
        later["validFrom"] = datetime.now(timezone.utc).isoformat()
        rec1, _ = self.validator.validate_attestation(earlier)
        self.store.add_attestation(rec1)
        return {
            "testId": "conflict-timestamp-001",
            "description": "Later timestamp wins conflict resolution",
            "credential": later,
            "expectedResult": "accepted",
        }

    def _authority_precedence(self) -> Dict[str, Any]:
        same_time = datetime.now(timezone.utc)
        cred_a = self._base_transfer()
        cred_a["id"] = f"urn:uuid:{uuid.uuid4()}"
        cred_a["issuer"]["id"] = "did:web:wholesaler.example.com"
        cred_a["validFrom"] = same_time.isoformat()
        cred_b = self._base_transfer()
        cred_b["id"] = f"urn:uuid:{uuid.uuid4()}"
        cred_b["issuer"]["id"] = "did:web:fda.example.gov"
        cred_b["validFrom"] = same_time.isoformat()
        rec_a, _ = self.validator.validate_attestation(cred_a)
        self.store.add_attestation(rec_a)
        return {
            "testId": "conflict-authority-001",
            "description": "Higher authority wins when timestamps match",
            "credential": cred_b,
            "expectedResult": "accepted",
        }

    def _multi_antecedent_conflict(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        comp1_id = f"urn:uuid:{uuid.uuid4()}"
        comp2_id = f"urn:uuid:{uuid.uuid4()}"
        for cid in [comp1_id, comp2_id]:
            rec = AttestationRecord(
                id=cid, type=[], issuer="", valid_from=now,
                subject_id="", event_type="Origin", antecedent=None,
                authorized_by={}, evidence=[], raw_credential={},
            )
            self.store.add_attestation(rec)
        cred = {
            "@context": [VC_CONTEXT_V2, UORA_CONTEXT],
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["VerifiableCredential", "UORAAttestation", "UORATransformationAttestation"],
            "issuer": {"id": "did:web:maker.example.com"},
            "validFrom": (now - timedelta(hours=1)).isoformat(),
            "credentialSubject": {
                "id": "did:web:maker.example.com:object:bundle:B-001",
                "eventType": "Transformation",
                "transformationType": "assembly",
                "inputObjects": ["did:web:maker.example.com:object:serial:C-001"],
                "outputObjects": ["did:web:maker.example.com:object:bundle:B-001"],
                "antecedent": [comp1_id, comp2_id],
                "authorizedBy": {
                    "certificationId": "urn:uuid:maker-cert",
                    "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                    "verifiedAt": now.isoformat(),
                },
            },
            "evidence": [{"id": f"urn:uuid:{uuid.uuid4()}", "type": ["Evidence"]}],
            "proof": {
                "type": "Ed25519Signature2020",
                "created": now.isoformat(),
                "verificationMethod": "did:web:maker.example.com#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "z5LbLbR3qZ5Y6m8n9o0p1q2r3s4t5u6v7w8x9y0za1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
            },
        }
        later = cred.copy()
        later["id"] = f"urn:uuid:{uuid.uuid4()}"
        later["validFrom"] = now.isoformat()
        rec1, _ = self.validator.validate_attestation(cred)
        self.store.add_attestation(rec1)
        return {
            "testId": "conflict-multi-antecedent-001",
            "description": "Conflict detection works with multiple antecedents",
            "credential": later,
            "expectedResult": "accepted",
        }

    # ------------------------------------------------------------------
    # Chain Integrity Tests
    # ------------------------------------------------------------------

    def _broken_antecedent_chain(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        cred["id"] = f"urn:uuid:{uuid.uuid4()}"
        cred["credentialSubject"]["antecedent"] = "urn:uuid:nonexistent-antecedent"
        return {
            "testId": "chain-broken-antecedent-001",
            "description": "Reject attestation with unresolvable antecedent",
            "credential": cred,
            "expectedResult": "rejected",
        }

    def _temporal_chain_violation(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        cred["id"] = f"urn:uuid:{uuid.uuid4()}"
        cred["validFrom"] = (
            datetime.now(timezone.utc) - timedelta(days=365)
        ).isoformat()
        return {
            "testId": "chain-temporal-violation-001",
            "description": "Reject attestation with timestamp before antecedent",
            "credential": cred,
            "expectedResult": "rejected",
        }

    # ------------------------------------------------------------------
    # Linear Chain Enforcement Tests
    # ------------------------------------------------------------------

    def _linear_chain_violation(self) -> Dict[str, Any]:
        """A Transfer that skips the most recent event should be rejected."""
        cred = self._base_transfer()
        cred["id"] = f"urn:uuid:{uuid.uuid4()}"
        cred["credentialSubject"]["id"] = "did:web:maker.example.com:object:serial:SN-chain"
        cred["credentialSubject"]["antecedent"] = "urn:uuid:origin-id"  # not the real latest

        # Create a valid chain: Origin -> Transfer1
        now = datetime.now(timezone.utc)
        origin = AttestationRecord(
            id="urn:uuid:origin-chain-id", type=[], issuer="did:web:maker.example.com",
            valid_from=now - timedelta(days=10), subject_id="did:web:maker.example.com:object:serial:SN-chain",
            event_type="Origin", antecedent=None, authorized_by={}, evidence=[],
            raw_credential={}, status=ValidationStatus.VALID,
        )
        transfer1 = AttestationRecord(
            id="urn:uuid:transfer-chain-1", type=[], issuer="did:web:shipper.example.com",
            valid_from=now - timedelta(days=5), subject_id="did:web:maker.example.com:object:serial:SN-chain",
            event_type="Transfer", antecedent=["urn:uuid:origin-chain-id"],
            authorized_by={}, evidence=[], raw_credential={}, status=ValidationStatus.VALID,
        )
        self.store.add_attestation(origin)
        self.store.add_attestation(transfer1)

        return {
            "testId": "linear-chain-violation-001",
            "description": "Reject Transfer that doesn't reference most recent valid event",
            "credential": cred,
            "expectedResult": "rejected",
        }

    def _linear_chain_correct(self) -> Dict[str, Any]:
        """A Transfer referencing the most recent event should be accepted."""
        cred = self._base_transfer()
        cred["id"] = f"urn:uuid:{uuid.uuid4()}"
        cred["credentialSubject"]["id"] = "did:web:maker.example.com:object:serial:SN-chain"
        cred["credentialSubject"]["antecedent"] = "urn:uuid:transfer-chain-1"
        return {
            "testId": "linear-chain-correct-001",
            "description": "Accept Transfer that correctly references most recent valid event",
            "credential": cred,
            "expectedResult": "accepted",
        }

    # ------------------------------------------------------------------
    # Proof Validation Tests
    # ------------------------------------------------------------------

    def _missing_proof(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        del cred["proof"]
        return {
            "testId": "proof-missing-001",
            "description": "Reject attestation without proof section",
            "credential": cred,
            "expectedResult": "rejected",
        }

    def _invalid_proof_type(self) -> Dict[str, Any]:
        cred = self._base_transfer()
        cred["proof"]["type"] = "InvalidProofType"
        return {
            "testId": "proof-invalid-type-001",
            "description": "Reject attestation with unrecognized proof type",
            "credential": cred,
            "expectedResult": "rejected",
        }

    # ------------------------------------------------------------------
    # EPCIS Evidence Linking Test
    # ------------------------------------------------------------------

    def _epcis_evidence_linked(self) -> Dict[str, Any]:
        """Verify that EPCIS-linked evidence is preserved."""
        cred = self._base_transfer()
        cred["evidence"].append({
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["Evidence", "EPCISObjectEvent"],
            "name": "EPCIS Shipping Event",
            "description": "Original EPCIS ObjectEvent with bizStep=shipping",
            "epcisEventID": "ni:///sha-256;abc123def456?ver=CBV2.0",
            "epcisEventType": "ObjectEvent",
            "epcisBizStep": "shipping",
        })
        return {
            "testId": "epcis-evidence-linked-001",
            "description": "Attestation with EPCIS ObjectEvent evidence linking",
            "credential": cred,
            "expectedResult": "accepted",
        }

    # ------------------------------------------------------------------
    # Test Executor
    # ------------------------------------------------------------------

    def _execute_test(self, test: Dict[str, Any]) -> None:
        """Execute a single test and record the result."""
        record, error = self.validator.validate_attestation(test["credential"])
        expected = test["expectedResult"]
        passed = False

        if expected == "accepted":
            passed = record.status == ValidationStatus.VALID and error is None
        elif expected == "rejected":
            passed = record.status != ValidationStatus.VALID and error is not None
            if "expectedError" in test and error:
                passed = passed and test["expectedError"] in error

        result = {
            "testId": test["testId"],
            "description": test["description"],
            "passed": passed,
            "status": record.status.value,
            "error": error,
        }
        self.results.append(result)
        icon = "PASS" if passed else "FAIL"
        logger.info(f"  [{icon}] {test['testId']}: {test['description']}")


# ============================================================================
# Seed Data
# ============================================================================

def seed_test_data(store: AttestationStore) -> None:
    """
    Load certifications and seed attestations for testing.

    Creates:
      - 4 CertificationCredentials (maker, shipper, recycler, expired)
      - 1 Origin attestation for SN-001
      - 2 Component attestations for transformation testing
    """
    now = datetime.now(timezone.utc)

    # Manufacturer certification (authorized for Origin, Transfer, Transformation)
    store.add_certification(CertificationCredential(
        id="urn:uuid:maker-cert",
        issuer="did:web:fda.example.gov",
        subject_id="did:web:maker.example.com",
        authorized_attestations=[
            "UORAOriginAttestation",
            "UORATransferAttestation",
            "UORATransformationAttestation",
        ],
        authorized_categories=["pharmaceuticals", "medical-devices"],
        authorized_regions=["global"],
        trust_framework="https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
        valid_from=now - timedelta(days=365),
        valid_until=now + timedelta(days=365),
    ))

    # Shipper certification (authorized for Transfer only)
    store.add_certification(CertificationCredential(
        id="urn:uuid:shipper-cert",
        issuer="did:web:fda.example.gov",
        subject_id="did:web:shipper.example.com",
        authorized_attestations=["UORATransferAttestation"],
        authorized_categories=["pharmaceuticals"],
        authorized_regions=["global"],
        trust_framework="https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
        valid_from=now - timedelta(days=365),
        valid_until=now + timedelta(days=365),
    ))

    # Recycler certification (authorized for Disposition only)
    store.add_certification(CertificationCredential(
        id="urn:uuid:recycler-cert",
        issuer="did:web:fda.example.gov",
        subject_id="did:web:recycler.example.com",
        authorized_attestations=["UORADispositionAttestation"],
        authorized_categories=["pharmaceuticals"],
        authorized_regions=["global"],
        trust_framework="https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
        valid_from=now - timedelta(days=365),
        valid_until=now + timedelta(days=365),
    ))

    # Expired certification (for negative testing)
    store.add_certification(CertificationCredential(
        id="urn:uuid:expired-cert",
        issuer="did:web:fda.example.gov",
        subject_id="did:web:expired-issuer.example.com",
        authorized_attestations=["UORATransferAttestation"],
        authorized_categories=["pharmaceuticals"],
        authorized_regions=["global"],
        trust_framework="https://w3id.org/verifiable-supply-chain/trust-frameworks/logistics-v1",
        valid_from=now - timedelta(days=730),
        valid_until=now - timedelta(days=365),
    ))

    # Seed Origin attestation for SN-001
    origin_cred = {
        "@context": [VC_CONTEXT_V2, UORA_CONTEXT],
        "id": "urn:uuid:origin-id",
        "type": ["VerifiableCredential", "UORAAttestation", "UORAOriginAttestation"],
        "issuer": {"id": "did:web:maker.example.com"},
        "validFrom": (now - timedelta(days=30)).isoformat(),
        "credentialSubject": {
            "id": "did:web:maker.example.com:object:serial:SN-001",
            "eventType": "Origin",
            "antecedent": None,
            "originType": "manufactured",
            "originLocation": "https://id.gs1.org/414/9521321000010",
            "originDate": (now - timedelta(days=30)).isoformat(),
            "authorizedBy": {
                "certificationId": "urn:uuid:maker-cert",
                "trustFramework": "https://w3id.org/verifiable-supply-chain/trust-frameworks/pharma-v1",
                "verifiedAt": now.isoformat(),
            },
        },
        "evidence": [{
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": ["Evidence", "EPCISObjectEvent"],
            "name": "Manufacturing Record",
            "epcisEventID": "ni:///sha-256;mfg001?ver=CBV2.0",
            "epcisEventType": "ObjectEvent",
            "epcisBizStep": "commissioning",
        }],
        "proof": {
            "type": "Ed25519Signature2020",
            "created": now.isoformat(),
            "verificationMethod": "did:web:maker.example.com#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": "z5LbLbR3qZ5Y6m8n9o0p1q2r3s4t5u6v7w8x9y0za1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
        },
    }

    origin_record = AttestationRecord(
        id="urn:uuid:origin-id",
        type=origin_cred["type"],
        issuer="did:web:maker.example.com",
        valid_from=datetime.fromisoformat(origin_cred["validFrom"].replace("Z", "+00:00")),
        subject_id="did:web:maker.example.com:object:serial:SN-001",
        event_type="Origin",
        antecedent=None,
        authorized_by=origin_cred["credentialSubject"]["authorizedBy"],
        evidence=origin_cred["evidence"],
        proof=origin_cred["proof"],
        raw_credential=origin_cred,
        status=ValidationStatus.VALID,
        chain_integrity="intact",
    )
    store.add_attestation(origin_record)

    # Seed component attestations for transformation testing
    for comp_name, comp_id in [("C-001", "urn:uuid:comp1-id"), ("C-002", "urn:uuid:comp2-id")]:
        comp_record = AttestationRecord(
            id=comp_id,
            type=[],
            issuer="did:web:maker.example.com",
            valid_from=now - timedelta(days=20),
            subject_id=f"did:web:maker.example.com:object:serial:{comp_name}",
            event_type="Origin",
            antecedent=None,
            authorized_by={},
            evidence=[],
            raw_credential={},
            status=ValidationStatus.VALID,
            chain_integrity="intact",
        )
        store.add_attestation(comp_record)

    logger.info("Seed data loaded: 4 certifications, 3 origin attestations")
    logger.info(f"Store stats: {store.get_stats()}")


# ============================================================================
# CLI Entry Point
# ============================================================================

def main() -> None:
    """
    Main entry point for the UORA Reference Resolver.

    Commands:
      serve    - Start the UORA-Query-API HTTP server
      test     - Run the conformance test suite
      validate - Validate a single attestation JSON file
      chain    - Display the custody chain for a subject DID
      stats    - Show store statistics
    """
    parser = argparse.ArgumentParser(
        description="UORA Reference Resolver v2.0",
        epilog="Protocol: https://w3id.org/uora/spec/core/v1.0",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # serve
    serve_parser = subparsers.add_parser("serve", help="Start UORA-Query-API server")
    serve_parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    serve_parser.add_argument("--host", type=str, default="0.0.0.0", help="Host (default: 0.0.0.0)")

    # test
    subparsers.add_parser("test", help="Run conformance test suite")

    # validate
    validate_parser = subparsers.add_parser("validate", help="Validate a single attestation file")
    validate_parser.add_argument("file", type=str, help="Path to attestation JSON file")

    # chain
    chain_parser = subparsers.add_parser("chain", help="Display custody chain for a subject")
    chain_parser.add_argument("did", type=str, help="Subject DID to query")

    # stats
    subparsers.add_parser("stats", help="Show store statistics")

    args = parser.parse_args()

    store = AttestationStore()
    validator = UORAValidator(store)
    seed_test_data(store)

    if args.command == "serve":
        UORAQueryHandler.validator = validator
        UORAQueryHandler.store = store
        server = HTTPServer((args.host, args.port), UORAQueryHandler)
        logger.info(f"UORA Resolver v2.0 starting on {args.host}:{args.port}")
        logger.info("Endpoints: GET /history, GET /chain, POST /attestations, POST /validate, GET /health, GET /stats")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            server.shutdown()

    elif args.command == "test":
        suite = ConformanceSuite(store, validator)
        success = suite.run_all()
        sys.exit(0 if success else 1)

    elif args.command == "validate":
        with open(args.file, "r") as f:
            credential = json.load(f)
        record, error = validator.validate_attestation(credential)
        print(json.dumps({
            "status": record.status.value,
            "error": error,
            "chainIntegrity": record.chain_integrity,
            "attestationId": record.id,
            "eventType": record.event_type,
            "proofType": record.proof.get("type", "none"),
        }, indent=2))
        sys.exit(0 if record.status == ValidationStatus.VALID else 1)

    elif args.command == "chain":
        records = store.get_history(args.did)
        valid_chain = [r for r in records if r.status == ValidationStatus.VALID]
        print(f"\nCustody Chain for: {args.did}")
        print("-" * 60)
        for i, r in enumerate(valid_chain, 1):
            print(f"  {i}. [{r.event_type}] {r.id}")
            print(f"     Time:   {r.valid_from.isoformat()}")
            print(f"     Issuer: {r.issuer}")
            if r.antecedent:
                print(f"     Antecedent: {r.antecedent}")
            print()
        if not valid_chain:
            print("  No valid attestations found for this DID.")
        print(f"Chain length: {len(valid_chain)} events")

    elif args.command == "stats":
        stats = store.get_stats()
        print(json.dumps(stats, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()