"""`.env.example` is where an operator learns what can be configured: every environment variable the
backend reads is on one line there, at its default, with what it does.

The variables read are found in the backend's source: `os.environ.get`, `os.getenv`, `os.environ[...]`,
`"NAME" in os.environ`, and the `_env_*` helpers of the settings module, each with the name as a literal.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / ".env.example"
# "# NAME=value   # meaning", or the same without the leading "# " once set
LINE = re.compile(r"^#?\s*([A-Z][A-Z0-9_]*)=(.*)$")
# written by the code for Django itself, never read as configuration
NOT_CONFIGURATION = {"DJANGO_SETTINGS_MODULE"}


def _is_environ(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "environ" and isinstance(node.value, ast.Name) and node.value.id == "os"


def _literal(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def backend_reads(source: str, where: str = "<source>") -> tuple[dict[str, ast.AST | None], list[str]]:
    """{variable: the default the code gives it, or None} and the reads whose name is not a literal."""
    found: dict[str, ast.AST | None] = {}
    unnamed: list[str] = []
    tree = ast.parse(source)
    helpers = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name.startswith("_env")}

    def inside_helper(node: ast.AST) -> bool:
        return any(isinstance(f, ast.FunctionDef) and f.name in helpers and node in ast.walk(f) for f in ast.walk(tree))

    def read(name_node: ast.AST, default: ast.AST | None, node: ast.AST) -> None:
        name = _literal(name_node)
        if name is None:
            # the settings helpers take the name as an argument; anywhere else the name must be visible here
            if not inside_helper(node):
                unnamed.append(f"{where}:{node.lineno}")
            return
        if name not in NOT_CONFIGURATION:
            found.setdefault(name, default)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.args:
            f = node.func
            default = node.args[1] if len(node.args) > 1 else None
            if isinstance(f, ast.Attribute) and f.attr == "get" and _is_environ(f.value):
                read(node.args[0], default, node)
            elif isinstance(f, ast.Attribute) and f.attr == "getenv" and isinstance(f.value, ast.Name) and f.value.id == "os":
                read(node.args[0], default, node)
            elif isinstance(f, ast.Name) and f.id in helpers:
                read(node.args[0], default, node)
        elif isinstance(node, ast.Subscript) and _is_environ(node.value) and isinstance(node.ctx, ast.Load):
            read(node.slice, None, node)
        elif isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.In) and _is_environ(node.comparators[0]):
            read(node.left, None, node)
    return found, unnamed


def all_backend_reads() -> tuple[dict[str, ast.AST | None], list[str]]:
    found: dict[str, ast.AST | None] = {}
    unnamed: list[str] = []
    for path in sorted((ROOT / "backend").rglob("*.py")):
        if any(part in ("data", "tmp") for part in path.relative_to(ROOT / "backend").parts[:1]):
            continue
        f, u = backend_reads(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))
        for name, default in f.items():
            found.setdefault(name, default)
        unnamed += u
    return found, unnamed


def listed() -> dict[str, tuple[str, str]]:
    """{variable: (value shown, the meaning after it)} from .env.example."""
    out: dict[str, tuple[str, str]] = {}
    for line in EXAMPLE.read_text(encoding="utf-8").splitlines():
        m = LINE.match(line.strip())
        if m:
            value, _, meaning = m.group(2).partition(" #")
            out[m.group(1)] = (value.strip(), meaning.strip())
    return out


def _shown(default: ast.AST | None) -> str | None:
    """How a default is written in .env.example, or None when the code computes it from something else."""
    if isinstance(default, ast.Constant):
        if isinstance(default.value, bool):
            return "1" if default.value else "0"
        if isinstance(default.value, (int, str)):
            return str(default.value)
    if isinstance(default, ast.BinOp) and isinstance(default.op, ast.Mult):
        left, right = _shown(default.left), _shown(default.right)
        if left and right and left.isdigit() and right.isdigit():
            return str(int(left) * int(right))
    # "<browser-only value> if FORENSIC_BROWSER_ONLY else <value>": the file shows the second and names the first
    if isinstance(default, ast.IfExp) and isinstance(default.test, ast.Name) and default.test.id == "FORENSIC_BROWSER_ONLY":
        return _shown(default.orelse)
    return None


def test_every_variable_the_backend_reads_is_in_the_example_file():
    found, unnamed = all_backend_reads()
    assert not unnamed, f"environment reads whose name is not a literal, so this test cannot list them: {unnamed}"
    missing = sorted(set(found) - set(listed()))
    assert not missing, f"read by the backend but not in .env.example: {missing}"


def test_every_variable_in_the_example_file_says_what_it_does():
    unexplained = sorted(name for name, (_, meaning) in listed().items() if len(meaning) < 3)
    assert not unexplained, f"no meaning after the value in .env.example: {unexplained}"


def test_the_example_file_shows_each_variable_at_its_default():
    found, _ = all_backend_reads()
    shown = listed()
    wrong = []
    for name, default in found.items():
        expected = _shown(default)
        if expected is not None and name in shown and shown[name][0] != expected:
            wrong.append(f"{name}: .env.example shows {shown[name][0]!r}, the code's default is {expected!r}")
    assert not wrong, "\n".join(wrong)


def test_a_new_read_anywhere_in_the_backend_is_found():
    source = 'import os\nA = os.environ.get("FORENSIC_NEW_ONE", "3")\nB = os.getenv("REMN_OTHER")\nC = os.environ["THIRD"]\nD = "FOURTH" in os.environ\n'
    found, unnamed = backend_reads(source)
    assert sorted(found) == ["FORENSIC_NEW_ONE", "FOURTH", "REMN_OTHER", "THIRD"]
    assert _shown(found["FORENSIC_NEW_ONE"]) == "3" and not unnamed
    # a name built at run time cannot be checked, so it is reported rather than skipped
    _, unnamed = backend_reads('import os\nname = "X"\nos.environ.get(name)\n')
    assert unnamed == ["<source>:3"]
