from __future__ import annotations

import pytest

from seclab.formal.ctl.ast import AG, And, Atom, EF, Implies, Not
from seclab.formal.ctl.errors import CTLError, CTLErrorCode
from seclab.formal.ctl.parser import parse_ctl
from seclab.formal.ctl.validator import validate_ctl_formula


def test_known_atoms_validate_against_vocabulary() -> None:
    formula = parse_ctl("AG(authenticated -> EF(charging))")

    validate_ctl_formula(formula, {"authenticated", "charging", "safe"})


def test_nested_unknown_atom_is_rejected() -> None:
    formula = parse_ctl("AG(!(safe && EF(missing)))")

    with pytest.raises(CTLError) as raised:
        validate_ctl_formula(formula, {"safe"})

    assert raised.value.code is CTLErrorCode.UNKNOWN_ATOM
    assert raised.value.token == "missing"


def test_atom_extraction_walks_the_ast() -> None:
    formula = AG(Implies(Atom("authenticated"), EF(And(Atom("safe"), Not(Atom("error"))))))

    with pytest.raises(CTLError) as raised:
        validate_ctl_formula(formula, {"authenticated", "safe"})

    assert raised.value.code is CTLErrorCode.UNKNOWN_ATOM
    assert raised.value.token == "error"
