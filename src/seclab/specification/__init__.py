"""Input contract and normalized specification models."""

from .schema import (
    Constraint, Domain, FunctionSpec, PropertySpec, Requirement, Specification, StateMachineSpec,
    StateSpec, TestSpec, TransitionSpec, Variable,
)
from .errors import SpecificationError, SpecificationErrorCode, SpecificationToolError
from .loader import LoadedSpecification, SourceDocument, load_specification
from .normalizer import normalize_specification
from .validator import validate_specification
from .validator import ValidatedSpecification
from .legacy_adapter import adapt_legacy_specification, is_legacy_teacher_specification, load_compatible_specification

__all__ = [
    "Constraint", "Domain", "FunctionSpec", "PropertySpec", "Requirement",
    "Specification", "StateMachineSpec", "StateSpec", "TestSpec", "TransitionSpec", "Variable",
    "LoadedSpecification", "SourceDocument", "SpecificationError",
    "SpecificationErrorCode", "load_specification", "normalize_specification",
    "SpecificationToolError", "validate_specification", "ValidatedSpecification",
    "adapt_legacy_specification", "is_legacy_teacher_specification", "load_compatible_specification",
]
