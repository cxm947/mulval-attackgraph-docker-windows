from __future__ import annotations

import csv
import re
import shutil
import subprocess
import time
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
            return f"{self.name}({','.join(str(x) for x in self.args)})"
        return self.name


@dataclass(frozen=True)
class Atom:
    pred: str
    args: Tuple[Term, ...]

    def __str__(self) -> str:
        return f"{self.pred}({','.join(str(x) for x in self.args)})"


@dataclass(frozen=True)
class Literal:
    atom: Optional[Atom] = None
    neq: Optional[Tuple[Term, Term]] = None


@dataclass(frozen=True)
class Rule:
    rule_id: int
    head: Atom
    body: Tuple[Literal, ...]
    label: str


@dataclass(frozen=True)
class Proof:
    rule: Rule
    parents: Tuple[Atom, ...]


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


@dataclass
class BatchItemResult:
    input_file: Path
    ok: bool
    elapsed_sec: float
    output_dir: Path
    error: str = ""


@dataclass
class BatchResult:
    total: int
    succeeded: int
    failed: int
    items: List[BatchItemResult]
    report_csv: Path


@dataclass
class _Node:
    node_id: int
    label: str
    node_type: str  # OR | AND | LEAF
    flag: int  # 0 OR/AND, 1 LEAF


def run_logic(config: LogicConfig) -> LogicResult:
    if not config.input_file.exists():
        raise LogicError(f"Input file not found: {config.input_file}")
    if not config.rules_file.exists():
        raise LogicError(f"Rules file not found: {config.rules_file}")
    config.output_dir.mkdir(parents=True, exist_ok=True)

    facts = _load_input_facts(config.input_file)
    rules, primitive_preds = _load_rules(config.rules_file)
    all_facts, proofs = _infer(facts, rules)
    goals = _extract_goals(facts)
    nodes, arcs = _build_mulval_graph(all_facts, goals, proofs, primitive_preds)
    result = _write_outputs(config.output_dir, nodes, arcs)
    _render_pdf(result.attackgraph_dot, result.attackgraph_pdf, config.dot_bin)
    _validate_outputs(result)
    return result


def discover_scenario_inputs(input_dir: Path, min_id: int = 1, max_id: int = 1000) -> List[Path]:
    items: List[Tuple[int, Path]] = []
    for p in sorted(input_dir.glob("S*.P")):
        m = re.fullmatch(r"S(\d+)\.P", p.name)
        if not m:
            continue
        n = int(m.group(1))
        if min_id <= n <= max_id:
            items.append((n, p))
    return [p for _, p in sorted(items, key=lambda x: x[0])]


def run_batch(
    input_files: Sequence[Path],
    rules_file: Path,
    output_root: Path,
    dot_bin: Optional[str] = None,
    continue_on_error: bool = True,
) -> BatchResult:
    if not rules_file.exists():
        raise LogicError(f"Rules file not found: {rules_file}")
    output_root.mkdir(parents=True, exist_ok=True)

    rules, primitive_preds = _load_rules(rules_file)
    items: List[BatchItemResult] = []
    for input_file in input_files:
        start = time.perf_counter()
        out_dir = output_root / input_file.stem
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            facts = _load_input_facts(input_file)
            all_facts, proofs = _infer(facts, rules)
            goals = _extract_goals(facts)
            nodes, arcs = _build_mulval_graph(all_facts, goals, proofs, primitive_preds)
            result = _write_outputs(out_dir, nodes, arcs)
            _render_pdf(result.attackgraph_dot, result.attackgraph_pdf, dot_bin)
            _validate_outputs(result)
            items.append(BatchItemResult(input_file=input_file, ok=True, elapsed_sec=time.perf_counter() - start, output_dir=out_dir))
        except Exception as exc:
            items.append(
                BatchItemResult(
                    input_file=input_file,
                    ok=False,
                    elapsed_sec=time.perf_counter() - start,
                    output_dir=out_dir,
                    error=str(exc),
                )
            )
            if not continue_on_error:
                break

    report = output_root / "batch_report.csv"
    with report.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["input_file", "ok", "elapsed_sec", "output_dir", "error"])
        for it in items:
            w.writerow([it.input_file.name, str(it.ok).lower(), f"{it.elapsed_sec:.3f}", str(it.output_dir), it.error])

    succeeded = sum(1 for x in items if x.ok)
    failed = len(items) - succeeded
    return BatchResult(total=len(items), succeeded=succeeded, failed=failed, items=items, report_csv=report)


def _load_input_facts(input_file: Path) -> List[Atom]:
    stmts = _split_statements(_strip_comments(input_file.read_text(encoding="utf-8", errors="ignore")))
    facts: List[Atom] = []
    for s in stmts:
        s = s.strip()
        if not s:
            continue
        if s.startswith(":-"):
            continue
        if ":-" in s:
            continue
        if "(" in s and ")" in s:
            facts.append(_parse_atom(s))
    return facts


def _load_rules(rules_file: Path) -> Tuple[List[Rule], set[str]]:
    stmts = _split_statements(_strip_comments(rules_file.read_text(encoding="utf-8", errors="ignore")))
    rules: List[Rule] = []
    primitive_preds: set[str] = set()
    rule_id = 0
    for raw in stmts:
        st = raw.strip()
        if not st:
            continue
        if st.startswith("primitive("):
            try:
                outer = _parse_atom(st)  # primitive(...)
                if len(outer.args) == 1 and outer.args[0].kind == "struct":
                    primitive_preds.add(outer.args[0].name)
            except Exception:
                pass
            continue
        if st.startswith("derived(") or st.startswith("meta(") or st.startswith(":-"):
            continue
        if st.startswith("interaction_rule("):
            head, body, label = _parse_interaction_rule(st)
            rules.append(Rule(rule_id=rule_id, head=head, body=body, label=label))
            rule_id += 1
            continue
    return rules, primitive_preds


def _infer(facts: List[Atom], rules: List[Rule]) -> Tuple[List[Atom], Dict[Atom, List[Proof]]]:
    fact_db: List[Atom] = []
    db_seen: set[Atom] = set()
    for f in facts:
        if f in db_seen:
            continue
        db_seen.add(f)
        fact_db.append(f)

    fact_set = {f for f in fact_db if _is_ground_atom(f)}
    proofs: Dict[Atom, List[Proof]] = {}
    proof_seen: set[Tuple[Atom, int, Tuple[Atom, ...]]] = set()

    changed = True
    while changed:
        changed = False
        snapshot = list(fact_db)
        for rule in rules:
            for subst, matched in _solve_body(rule.body, snapshot, {}):
                head = _apply_atom(rule.head, subst)
                if head is None:
                    continue
                parents = tuple(matched)
                key = (head, rule.rule_id, parents)
                if key not in proof_seen:
                    proof_seen.add(key)
                    proofs.setdefault(head, []).append(Proof(rule=rule, parents=parents))
                if head not in fact_set:
                    fact_set.add(head)
                    if head not in db_seen:
                        db_seen.add(head)
                        fact_db.append(head)
                    changed = True

    return sorted(fact_set, key=str), proofs


def _solve_body(
    body: Sequence[Literal],
    facts: List[Atom],
    subst: Dict[str, Term],
    matched: Optional[List[Tuple[Atom, Atom]]] = None,
):
    matched = matched or []
    if not body:
        realized: List[Atom] = []
        for q_atom, fact_atom in matched:
            inst = _apply_atom(q_atom, subst)
            if inst is not None:
                realized.append(inst)
            else:
                realized.append(fact_atom)
        yield subst, realized
        return
    head = body[0]
    tail = body[1:]

    if head.neq is not None:
        l = _resolve_term(head.neq[0], subst)
        r = _resolve_term(head.neq[1], subst)
        if l.kind == "var" or r.kind == "var":
            return
        if str(l) != str(r):
            yield from _solve_body(tail, facts, subst, matched)
        return

    assert head.atom is not None
    if head.atom.pred == "dif" and len(head.atom.args) == 2:
        l = _resolve_term(head.atom.args[0], subst)
        r = _resolve_term(head.atom.args[1], subst)
        if l.kind == "var" or r.kind == "var":
            return
        if str(l) != str(r):
            yield from _solve_body(tail, facts, subst, matched)
        return

    for fact in facts:
        if fact.pred != head.atom.pred or len(fact.args) != len(head.atom.args):
            continue
        ns = _unify_atoms(head.atom, fact, subst)
        if ns is None:
            continue
        yield from _solve_body(tail, facts, ns, matched + [(head.atom, fact)])


def _unify_atoms(pattern: Atom, fact: Atom, subst: Dict[str, Term]) -> Optional[Dict[str, Term]]:
    if pattern.pred != fact.pred or len(pattern.args) != len(fact.args):
        return None
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
        if term.name in subst:
            return _resolve_term(subst[term.name], subst)
        return term
    if term.kind == "struct":
        return Term("struct", term.name, tuple(_resolve_term(a, subst) for a in term.args))
    return term


def _extract_goals(facts: List[Atom]) -> List[Atom]:
    goals: List[Atom] = []
    for f in facts:
        if f.pred == "attackGoal" and len(f.args) == 1 and f.args[0].kind == "struct":
            s = f.args[0]
            goals.append(Atom(s.name, s.args))
    return goals


def _build_mulval_graph(
    all_facts: List[Atom],
    goals: List[Atom],
    proofs: Dict[Atom, List[Proof]],
    primitive_preds: set[str],
) -> Tuple[List[_Node], List[Tuple[int, int, int]]]:
    all_set = set(all_facts)
    targets: List[Atom] = []
    if goals:
        for g in goals:
            for f in all_set:
                if _unify_atoms(g, f, {}) is not None:
                    targets.append(f)
    if not targets:
        targets = list(proofs.keys())
    targets = sorted(set(targets), key=str)

    nodes: List[_Node] = []
    arcs: List[Tuple[int, int, int]] = []  # (to, from, -1)
    arc_seen: set[Tuple[int, int]] = set()
    next_id = 1

    atom_to_id: Dict[Tuple[str, Atom], int] = {}  # kind OR/LEAF + atom -> id
    and_to_id: Dict[Tuple[Atom, int, Tuple[Atom, ...]], int] = {}
    in_progress: set[Atom] = set()

    def add_node(label: str, node_type: str, flag: int) -> int:
        nonlocal next_id
        nid = next_id
        next_id += 1
        nodes.append(_Node(node_id=nid, label=label, node_type=node_type, flag=flag))
        return nid

    def add_arc(to_id: int, from_id: int) -> None:
        k = (to_id, from_id)
        if k in arc_seen:
            return
        arc_seen.add(k)
        arcs.append((to_id, from_id, -1))

    def emit_atom(atom: Atom) -> int:
        if atom.pred not in primitive_preds and atom in proofs:
            return emit_or(atom)
        key = ("LEAF", atom)
        if key in atom_to_id:
            return atom_to_id[key]
        nid = add_node(str(atom), "LEAF", 1)
        atom_to_id[key] = nid
        return nid

    def emit_or(atom: Atom) -> int:
        key = ("OR", atom)
        if key in atom_to_id:
            return atom_to_id[key]
        nid = add_node(str(atom), "OR", 0)
        atom_to_id[key] = nid

        if atom in in_progress:
            return nid
        in_progress.add(atom)

        for pf in sorted(
            proofs.get(atom, []),
            key=lambda p: (p.rule.rule_id, p.rule.label, tuple(str(x) for x in p.parents)),
        ):
            and_key = (atom, pf.rule.rule_id, pf.parents)
            and_id = and_to_id.get(and_key)
            if and_id is None:
                and_label = f"RULE {pf.rule.rule_id} ({pf.rule.label})"
                and_id = add_node(and_label, "AND", 0)
                and_to_id[and_key] = and_id
            add_arc(nid, and_id)
            for parent in pf.parents:
                if parent.pred == "attackGoal":
                    continue
                parent_id = emit_atom(parent)
                add_arc(and_id, parent_id)

        in_progress.remove(atom)
        return nid

    for tgt in targets:
        emit_or(tgt)

    return nodes, arcs


def _write_outputs(output_dir: Path, nodes: List[_Node], arcs: List[Tuple[int, int, int]]) -> LogicResult:
    vertices = output_dir / "VERTICES.CSV"
    arcs_csv = output_dir / "ARCS.CSV"
    attack_txt = output_dir / "AttackGraph.txt"
    dot = output_dir / "AttackGraph.dot"
    pdf = output_dir / "AttackGraph.pdf"

    with vertices.open("w", newline="", encoding="utf-8") as f:
        for n in nodes:
            f.write(_vertex_line(n) + "\n")

    with arcs_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for to_id, from_id, val in arcs:
            w.writerow([to_id, from_id, val])

    arcs_by_to: Dict[int, List[Tuple[int, int, int]]] = {}
    for a in arcs:
        arcs_by_to.setdefault(a[0], []).append(a)

    with attack_txt.open("w", encoding="utf-8", newline="\n") as f:
        for n in nodes:
            f.write(_vertex_line(n) + "\n")
            for to_id, from_id, val in arcs_by_to.get(n.node_id, []):
                f.write(f"{to_id},{from_id},{val}\n")

    shape = {"LEAF": "box", "AND": "ellipse", "OR": "diamond"}
    with dot.open("w", encoding="utf-8", newline="\n") as f:
        f.write("digraph G {\n")
        for n in nodes:
            label = f"{n.node_id}:{n.label}:{n.flag}".replace('"', '\\"')
            f.write(f'\t{n.node_id} [label="{label}",shape={shape[n.node_type]}];\n')
        for to_id, from_id, _ in arcs:
            f.write(f"\t{from_id} -> \t{to_id};\n")
        f.write("}\n")

    return LogicResult(vertices_csv=vertices, arcs_csv=arcs_csv, attackgraph_txt=attack_txt, attackgraph_pdf=pdf, attackgraph_dot=dot)


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


def _validate_outputs(result: LogicResult) -> None:
    req = [result.vertices_csv, result.arcs_csv, result.attackgraph_txt, result.attackgraph_pdf]
    missing = [str(p) for p in req if not p.exists()]
    if missing:
        raise LogicError(f"Missing output files: {', '.join(missing)}")
    empty = [str(p) for p in req if p.stat().st_size == 0]
    if empty:
        raise LogicError(f"Empty output files: {', '.join(empty)}")


def _is_ground_atom(atom: Atom) -> bool:
    return all(_is_ground_term(x) for x in atom.args)


def _is_ground_term(t: Term) -> bool:
    if t.kind == "var":
        return False
    if t.kind == "struct":
        return all(_is_ground_term(x) for x in t.args)
    return True


def _parse_interaction_rule(stmt: str) -> Tuple[Atom, Tuple[Literal, ...], str]:
    inside = stmt[len("interaction_rule(") :].strip()
    if inside.endswith(")"):
        inside = inside[:-1].strip()
    first, second = _split_top_level_first_comma(inside)
    first = _strip_outer_parens(first.strip())
    head_s, body_s = _split_top_level(first, ":-")
    head = _parse_atom(head_s.strip())
    body = tuple(_parse_literal(x.strip()) for x in _split_top_level_commas(body_s.strip()))
    label = "interaction_rule"
    m = re.search(r"rule_desc\s*\(\s*'([^']+)'", second)
    if m:
        label = m.group(1)
    return head, body, label


def _parse_literal(text: str) -> Literal:
    if "\\=" in text:
        l, r = _split_top_level(text, "\\=")
        return Literal(neq=(_parse_term(l.strip()), _parse_term(r.strip())))
    return Literal(atom=_parse_atom(text))


def _parse_atom(text: str) -> Atom:
    name, args_s = _split_name_args(text.strip())
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
    return text[:i].strip(), text[i + 1 : -1].strip()


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    lines: List[str] = []
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
    raise LogicError(f"Operator {op} not found at top level: {text}")


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
    raise LogicError(f"Cannot split top-level comma in: {text}")


def _split_top_level_commas(text: str) -> List[str]:
    out: List[str] = []
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
                out.append("".join(cur).strip())
                cur = []
                continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _strip_outer_parens(text: str) -> str:
    text = text.strip()
    if text.startswith("(") and text.endswith(")"):
        return text[1:-1].strip()
    return text


def _csv_line(items: List[object]) -> str:
    buf: List[str] = []
    for x in items:
        s = str(x)
        if any(ch in s for ch in [",", '"']):
            s = '"' + s.replace('"', '""') + '"'
        buf.append(s)
    return ",".join(buf)


def _vertex_line(node: _Node) -> str:
    # Match MulVAL style: id,"label","TYPE",flag
    label = str(node.label).replace('"', '""')
    ntype = str(node.node_type).replace('"', '""')
    return f'{node.node_id},"{label}","{ntype}",{node.flag}'
