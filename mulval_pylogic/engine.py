from __future__ import annotations

import csv
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


class LogicError(RuntimeError):
    pass


@dataclass(frozen=True)
class Term:
    kind: str  # const | var | struct
    name: str
    args: Tuple["Term", ...] = ()

    def __str__(self) -> str:
        if self.kind == "struct":
            return f"{self.name}({', '.join(str(x) for x in self.args)})"
        return self.name


@dataclass(frozen=True)
class Atom:
    pred: str
    args: Tuple[Term, ...]

    def __str__(self) -> str:
        return f"{self.pred}({', '.join(str(x) for x in self.args)})"


@dataclass(frozen=True)
class Literal:
    atom: Optional[Atom] = None
    neq: Optional[Tuple[Term, Term]] = None


@dataclass(frozen=True)
class Rule:
    head: Atom
    body: Tuple[Literal, ...]
    label: str


@dataclass
class LogicConfig:
    input_file: Path
    rules_file: Path
    output_dir: Path
    dot_bin: Optional[str] = None


@dataclass
class LogicResult:
    vertices_csv: Path
    arcs_csv: Path
    attackgraph_txt: Path
    attackgraph_pdf: Path
    attackgraph_dot: Path


def run_logic(config: LogicConfig) -> LogicResult:
    if not config.input_file.exists():
        raise LogicError(f"Input file not found: {config.input_file}")
    if not config.rules_file.exists():
        raise LogicError(f"Rules file not found: {config.rules_file}")
    config.output_dir.mkdir(parents=True, exist_ok=True)

    facts, rules = _load_program(config.input_file, config.rules_file)
    derived, provenance = _infer(facts, rules)
    goals = _extract_goals(facts)
    nodes, edges = _build_graph(facts, derived, goals, provenance)
    result = _write_outputs(config.output_dir, nodes, edges)
    _render_pdf(result.attackgraph_dot, result.attackgraph_pdf, config.dot_bin)
    return result


def _load_program(input_file: Path, rules_file: Path) -> Tuple[List[Atom], List[Rule]]:
    input_stmts = _split_statements(_strip_comments(input_file.read_text(encoding="utf-8", errors="ignore")))
    rules_stmts = _split_statements(_strip_comments(rules_file.read_text(encoding="utf-8", errors="ignore")))

    facts: List[Atom] = []
    rules: List[Rule] = []

    for s in input_stmts:
        s = s.strip()
        if not s:
            continue
        if s.startswith("attackGoal(") or (not s.startswith(":-") and ":-" not in s):
            atom = _parse_atom(s)
            facts.append(atom)

    for s in rules_stmts:
        st = s.strip()
        if not st:
            continue
        if st.startswith("primitive(") or st.startswith("derived(") or st.startswith("meta(") or st.startswith(":-"):
            continue
        if st.startswith("interaction_rule("):
            rule = _parse_interaction_rule(st)
            rules.append(rule)
            continue
        if ":-" in st:
            head_s, body_s = _split_top_level(st, ":-")
            head = _parse_atom(head_s.strip())
            body = tuple(_parse_literal(x.strip()) for x in _split_top_level_commas(body_s.strip()))
            rules.append(Rule(head=head, body=body, label="rule"))
            continue
        if st.startswith("attackGoal("):
            # goal already loaded from input, ignore rules file goals if any
            continue
        # direct facts inside rules file are allowed
        if "(" in st and ")" in st:
            facts.append(_parse_atom(st))

    return facts, rules


def _infer(facts: List[Atom], rules: List[Rule]) -> Tuple[List[Atom], Dict[Atom, Tuple[str, List[Atom]]]]:
    fact_set = {f for f in facts if _is_ground_atom(f)}
    provenance: Dict[Atom, Tuple[str, List[Atom]]] = {}

    changed = True
    while changed:
        changed = False
        for rule in rules:
            for subst, matched_atoms in _solve_body(rule.body, list(fact_set), {}):
                grounded = _apply_atom(rule.head, subst)
                if grounded is None:
                    continue
                if grounded not in fact_set:
                    fact_set.add(grounded)
                    provenance[grounded] = (rule.label, matched_atoms)
                    changed = True
    return sorted(fact_set, key=str), provenance


def _solve_body(
    body: Sequence[Literal],
    facts: List[Atom],
    subst: Dict[str, Term],
    matched: Optional[List[Atom]] = None,
):
    matched = matched or []
    if not body:
        yield subst, matched
        return

    head = body[0]
    tail = body[1:]

    if head.neq is not None:
        left = _resolve_term(head.neq[0], subst)
        right = _resolve_term(head.neq[1], subst)
        if left.kind == "var" or right.kind == "var":
            return
        if str(left) != str(right):
            yield from _solve_body(tail, facts, subst, matched)
        return

    assert head.atom is not None
    for fact in facts:
        if fact.pred != head.atom.pred or len(fact.args) != len(head.atom.args):
            continue
        ns = _unify_atoms(head.atom, fact, subst)
        if ns is None:
            continue
        yield from _solve_body(tail, facts, ns, matched + [fact])


def _unify_atoms(pattern: Atom, fact: Atom, subst: Dict[str, Term]) -> Optional[Dict[str, Term]]:
    ns = dict(subst)
    for pt, fv in zip(pattern.args, fact.args):
        ns = _unify_term(pt, fv, ns)
        if ns is None:
            return None
    return ns


def _unify_term(left: Term, right: Term, subst: Dict[str, Term]) -> Optional[Dict[str, Term]]:
    if left.kind == "var":
        if left.name == "_":
            return subst
        bound = subst.get(left.name)
        if bound is None:
            ns = dict(subst)
            ns[left.name] = right
            return ns
        return _unify_term(bound, right, subst)

    if right.kind == "var":
        return _unify_term(right, left, subst)

    if left.kind != right.kind or left.name != right.name or len(left.args) != len(right.args):
        return None

    ns = dict(subst)
    for la, ra in zip(left.args, right.args):
        ns = _unify_term(la, ra, ns)
        if ns is None:
            return None
    return ns


def _apply_atom(atom: Atom, subst: Dict[str, Term]) -> Optional[Atom]:
    args: List[Term] = []
    for a in atom.args:
        ra = _resolve_term(a, subst)
        if ra.kind == "var":
            return None
        args.append(ra)
    return Atom(atom.pred, tuple(args))


def _resolve_term(term: Term, subst: Dict[str, Term]) -> Term:
    if term.kind == "var":
        if term.name == "_":
            return term
        if term.name in subst:
            return _resolve_term(subst[term.name], subst)
        return term
    if term.kind == "struct":
        return Term("struct", term.name, tuple(_resolve_term(a, subst) for a in term.args))
    return term


def _extract_goals(facts: List[Atom]) -> List[Atom]:
    patterns: List[Atom] = []
    for f in facts:
        if f.pred == "attackGoal" and len(f.args) == 1 and f.args[0].kind == "struct":
            s = f.args[0]
            patterns.append(Atom(s.name, s.args))
    return patterns


def _build_graph(
    base_facts: List[Atom],
    all_facts: List[Atom],
    goals: List[Atom],
    provenance: Dict[Atom, Tuple[str, List[Atom]]],
):
    all_set = set(all_facts)
    target_nodes: List[Atom] = []
    if goals:
        for g in goals:
            for f in all_set:
                if _unify_atoms(g, f, {}) is not None:
                    target_nodes.append(f)
    else:
        target_nodes = [f for f in all_facts if f in provenance]

    keep: set[Atom] = set()
    edges: List[Tuple[Atom, Atom, str]] = []

    stack = list(target_nodes)
    while stack:
        cur = stack.pop()
        if cur in keep:
            continue
        keep.add(cur)
        prov = provenance.get(cur)
        if not prov:
            continue
        label, parents = prov
        for p in parents:
            edges.append((p, cur, label))
            if p not in keep:
                stack.append(p)

    if not keep:
        keep = set(base_facts)

    nodes = sorted(keep, key=str)
    return nodes, edges


def _write_outputs(output_dir: Path, nodes: List[Atom], edges: List[Tuple[Atom, Atom, str]]) -> LogicResult:
    node_id: Dict[Atom, int] = {n: i + 1 for i, n in enumerate(nodes)}

    vertices = output_dir / "VERTICES.CSV"
    arcs = output_dir / "ARCS.CSV"
    txt = output_dir / "AttackGraph.txt"
    dot = output_dir / "AttackGraph.dot"
    pdf = output_dir / "AttackGraph.pdf"

    with vertices.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "label", "type"])
        for n in nodes:
            ntype = "goal" if n.pred in ("execCode", "attackVectorInjection", "getAccount", "netAccess") else "fact"
            w.writerow([node_id[n], str(n), ntype])

    with arcs.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["src", "dst", "rule"])
        for src, dst, label in edges:
            if src in node_id and dst in node_id:
                w.writerow([node_id[src], node_id[dst], label])

    with txt.open("w", encoding="utf-8") as f:
        f.write("Vertices:\n")
        for n in nodes:
            f.write(f"{node_id[n]}: {n}\n")
        f.write("\nEdges:\n")
        for src, dst, label in edges:
            if src in node_id and dst in node_id:
                f.write(f"{node_id[src]} -> {node_id[dst]} ({label})\n")

    with dot.open("w", encoding="utf-8") as f:
        f.write("digraph AttackGraph {\n")
        f.write("  rankdir=LR;\n")
        for n in nodes:
            label = str(n).replace('"', '\\"')
            f.write(f'  n{node_id[n]} [label="{label}"];\n')
        for src, dst, _ in edges:
            if src in node_id and dst in node_id:
                f.write(f"  n{node_id[src]} -> n{node_id[dst]};\n")
        f.write("}\n")

    return LogicResult(vertices_csv=vertices, arcs_csv=arcs, attackgraph_txt=txt, attackgraph_pdf=pdf, attackgraph_dot=dot)


def _render_pdf(dot_file: Path, pdf_file: Path, preferred_dot: Optional[str]) -> None:
    dot = preferred_dot or shutil.which("dot")
    if not dot:
        common = Path(r"C:\Program Files\Graphviz\bin\dot.exe")
        if common.exists():
            dot = str(common)
    if not dot:
        raise LogicError("Graphviz dot not found. Install Graphviz to generate AttackGraph.pdf.")
    cp = subprocess.run([dot, "-Tpdf", str(dot_file), "-o", str(pdf_file)], capture_output=True, text=True)
    if cp.returncode != 0:
        raise LogicError(f"dot render failed: {cp.stderr.strip() or cp.stdout.strip()}")


def _is_ground_atom(atom: Atom) -> bool:
    return all(_is_ground_term(t) for t in atom.args)


def _is_ground_term(t: Term) -> bool:
    if t.kind == "var":
        return False
    if t.kind == "struct":
        return all(_is_ground_term(a) for a in t.args)
    return True


def _parse_interaction_rule(stmt: str) -> Rule:
    inside = stmt[len("interaction_rule(") :].strip()
    if inside.endswith(")"):
        inside = inside[:-1].strip()
    first_arg, second_arg = _split_top_level_first_comma(inside)
    first_arg = _strip_outer_parens(first_arg.strip())
    head_s, body_s = _split_top_level(first_arg, ":-")
    head = _parse_atom(head_s.strip())
    body = tuple(_parse_literal(x.strip()) for x in _split_top_level_commas(body_s.strip()))
    label = "interaction_rule"
    m = re.search(r"rule_desc\s*\(\s*'([^']+)'", second_arg)
    if m:
        label = m.group(1)
    return Rule(head=head, body=body, label=label)


def _parse_literal(text: str) -> Literal:
    if "\\=" in text:
        l, r = _split_top_level(text, "\\=")
        return Literal(neq=(_parse_term(l.strip()), _parse_term(r.strip())))
    return Literal(atom=_parse_atom(text))


def _parse_atom(text: str) -> Atom:
    text = text.strip()
    name, args_s = _split_name_args(text)
    args = tuple(_parse_term(x.strip()) for x in _split_top_level_commas(args_s))
    return Atom(name, args)


def _parse_term(text: str) -> Term:
    text = text.strip()
    if text.startswith("'") and text.endswith("'"):
        return Term("const", text)

    if "(" in text and text.endswith(")"):
        name, args_s = _split_name_args(text)
        args = tuple(_parse_term(x.strip()) for x in _split_top_level_commas(args_s))
        return Term("struct", name, args)

    if text and (text[0].isupper() or text[0] == "_"):
        return Term("var", text)
    return Term("const", text)


def _split_name_args(text: str) -> Tuple[str, str]:
    i = text.find("(")
    if i < 0 or not text.endswith(")"):
        raise LogicError(f"Invalid atom/term: {text}")
    name = text[:i].strip()
    return name, text[i + 1 : -1].strip()


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    lines = []
    for line in text.splitlines():
        if "%" in line:
            line = line.split("%", 1)[0]
        lines.append(line)
    return "\n".join(lines)


def _split_statements(text: str) -> List[str]:
    out: List[str] = []
    cur: List[str] = []
    depth = 0
    quote = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "'" and (i == 0 or text[i - 1] != "\\"):
            quote = not quote
            cur.append(ch)
            i += 1
            continue
        if not quote:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            elif ch == "." and depth == 0:
                stmt = "".join(cur).strip()
                if stmt:
                    out.append(stmt)
                cur = []
                i += 1
                continue
        cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _split_top_level(text: str, op: str) -> Tuple[str, str]:
    depth = 0
    quote = False
    i = 0
    while i <= len(text) - len(op):
        ch = text[i]
        if ch == "'" and (i == 0 or text[i - 1] != "\\"):
            quote = not quote
            i += 1
            continue
        if not quote:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif depth == 0 and text[i : i + len(op)] == op:
                return text[:i], text[i + len(op) :]
        i += 1
    raise LogicError(f"Operator {op} not found at top-level: {text}")


def _split_top_level_first_comma(text: str) -> Tuple[str, str]:
    depth = 0
    quote = False
    for i, ch in enumerate(text):
        if ch == "'" and (i == 0 or text[i - 1] != "\\"):
            quote = not quote
            continue
        if quote:
            continue
        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            depth -= 1
            continue
        if ch == "," and depth == 0:
            return text[:i], text[i + 1 :]
    raise LogicError(f"Cannot split top-level args: {text}")


def _split_top_level_commas(text: str) -> List[str]:
    items: List[str] = []
    cur: List[str] = []
    depth = 0
    quote = False
    for i, ch in enumerate(text):
        if ch == "'" and (i == 0 or text[i - 1] != "\\"):
            quote = not quote
            cur.append(ch)
            continue
        if not quote:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                items.append("".join(cur).strip())
                cur = []
                continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        items.append(tail)
    return items


def _strip_outer_parens(text: str) -> str:
    text = text.strip()
    if text.startswith("(") and text.endswith(")"):
        return text[1:-1].strip()
    return text
