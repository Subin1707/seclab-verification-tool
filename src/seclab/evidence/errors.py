"""Errors raised by evidence storage and manifest contracts."""

from enum import StrEnum


class EvidenceErrorCode(StrEnum):
    DUPLICATE_EVIDENCE_ID = "DUPLICATE_EVIDENCE_ID"
    INVALID_EVIDENCE = "INVALID_EVIDENCE"
    INVALID_ARTIFACT_PATH = "INVALID_ARTIFACT_PATH"
    ARTIFACT_WRITE_ERROR = "ARTIFACT_WRITE_ERROR"
    ARTIFACT_ALREADY_EXISTS = "ARTIFACT_ALREADY_EXISTS"
    ARTIFACT_SERIALIZATION_ERROR = "ARTIFACT_SERIALIZATION_ERROR"
    MANIFEST_SERIALIZATION_ERROR = "MANIFEST_SERIALIZATION_ERROR"
    MISSING_EVIDENCE_REFERENCE = "MISSING_EVIDENCE_REFERENCE"


class EvidenceError(Exception):
    category = "EVIDENCE_ERROR"

    def __init__(self, code: EvidenceErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")
