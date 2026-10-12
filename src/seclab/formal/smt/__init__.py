"""SMT expression parsing, encoding and verification."""

from .ast import Binary, Expr, Literal, Unary, Variable
from .counterexample import Counterexample, ModelAssignment
from .encoder import EncodedQuery, QueryIntent, SMTEncoder
from .evaluator import evaluate_expression, validate_model
from .errors import SMTError, SMTErrorCode
from .parser import parse_expression
from .solver import BackendResult, SMTCheck, SolverBackend, SolverOutcome, SMTVerifier, Z3SolverBackend
from .validator import ValueType, domain_type, infer_type, type_environment

__all__ = [
    "BackendResult", "Binary", "Counterexample", "EncodedQuery", "Expr", "Literal", "ModelAssignment",
    "QueryIntent", "SMTCheck", "SMTEncoder", "SMTError", "SMTErrorCode", "SMTVerifier", "SolverBackend",
    "SolverOutcome", "Unary", "ValueType", "Variable", "Z3SolverBackend", "domain_type", "infer_type",
    "parse_expression", "type_environment", "validate_model", "evaluate_expression",
]
