#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import sys
from collections import defaultdict

DIV_Q_RE = re.compile(
    r'<div\b[^>]*\bdata-question-id\s*=\s*"(\d+)"[^>]*>',
    re.IGNORECASE
)

DIV_Q_WITH_ATTRS_RE = re.compile(
    r'<div\b([^>]*)\bdata-question-id\s*=\s*"(\d+)"([^>]*)>',
    re.IGNORECASE
)

VARIANT_RE = re.compile(
    r'\bdata-question-variant\s*=\s*"([^"]+)"',
    re.IGNORECASE
)

OPTIONS_BLOCK_RE = re.compile(
    r'<div\b[^>]*\bdata-role\s*=\s*"options"[^>]*>',
    re.IGNORECASE
)

OPTION_P_RE = re.compile(
    r'<p\b[^>]*\bdata-option\s*=\s*"([ABCD])"[^>]*>',
    re.IGNORECASE
)


def extract_questions(html: str):
    """
    Retorna lista de dicts:
      - qid: int
      - variant: str ('' se ausente)
      - pos: posição no arquivo
    """
    out = []
    for m in DIV_Q_WITH_ATTRS_RE.finditer(html):
        attrs_left, qid, attrs_right = m.group(1), m.group(2), m.group(3)
        attrs = f"{attrs_left} {attrs_right}"
        variant = ""
        vm = VARIANT_RE.search(attrs)
        if vm:
            variant = vm.group(1).strip()
        out.append(
            {"qid": int(qid), "variant": variant, "pos": m.start()}
        )
    return out


def slice_div_block(html: str, start_pos: int) -> str:
    """
    Isola o bloco <div ...data-question-id...>...</div>
    (best-effort, assume que questões não são aninhadas).
    """
    open_tag_end = html.find(">", start_pos)
    if open_tag_end < 0:
        return ""

    depth = 0
    i = start_pos

    while i < len(html):
        next_open = html.find("<div", i)
        next_close = html.find("</div", i)

        if next_close == -1:
            return ""

        if next_open != -1 and next_open < next_close:
            if next_open == start_pos:
                depth = 1
            else:
                depth += 1
            i = next_open + 4
        else:
            depth -= 1
            i = next_close + 5
            if depth == 0:
                end = html.find(">", next_close)
                if end == -1:
                    return ""
                return html[start_pos:end + 1]

    return ""


def validate_file(path: str, expect_min: int = 1, expect_max: int = 50):
    html = open(path, "r", encoding="utf-8").read()

    questions = extract_questions(html)
    if not questions:
        return False, [f"[ERROR] Nenhuma questão encontrada em {path}."]

    questions_sorted = sorted(questions, key=lambda x: x["pos"])

    # IDs presentes
    ids_present = set(q["qid"] for q in questions_sorted)
    missing = [i for i in range(expect_min, expect_max + 1) if i not in ids_present]

    # Agrupar por ID
    by_id = defaultdict(list)
    for q in questions_sorted:
        by_id[q["qid"]].append(q)

    expected_dups = []
    problematic_dups = []
    needs_variant = []

    for qid, occ in sorted(by_id.items()):
        if len(occ) == 1:
            continue

        variants = [o["variant"] for o in occ]
        vset = set(variants)

        if "" in vset:
            if qid in {11, 12, 13, 14, 15}:
                needs_variant.append(qid)
            else:
                problematic_dups.append((qid, variants))
            continue

        if qid in {11, 12, 13, 14, 15} and vset == {"espanhol", "ingles"} and len(occ) == 2:
            expected_dups.append((qid, variants))
        else:
            problematic_dups.append((qid, variants))

    # Estrutura
    structure_errors = []
    for q in questions_sorted:
        block = slice_div_block(html, q["pos"])
        if not block:
            structure_errors.append(f"[ERROR] Q{q['qid']}: não foi possível isolar o bloco.")
            continue

        options_blocks = list(OPTIONS_BLOCK_RE.finditer(block))
        if len(options_blocks) != 1:
            structure_errors.append(
                f"[ERROR] Q{q['qid']}: {len(options_blocks)} blocos data-role=\"options\" (esperado 1)."
            )
            continue

        opts = set(m.group(1) for m in OPTION_P_RE.finditer(block))
        missing_opts = [x for x in ["A", "B", "C", "D"] if x not in opts]
        if missing_opts:
            structure_errors.append(
                f"[ERROR] Q{q['qid']}: alternativas ausentes {', '.join(missing_opts)}."
            )

    report = []
    report.append(f"[OK] Arquivo validado: {path}")
    report.append(f"[INFO] Total de questões (contando variantes): {len(questions_sorted)}")
    report.append(f"[INFO] IDs únicos encontrados: {len(ids_present)}")

    if missing:
        report.append(f"[ERROR] IDs ausentes: {', '.join(map(str, missing))}")
    else:
        report.append("[OK] IDs 1–50 completos.")

    if expected_dups:
        report.append("[OK] Duplicações esperadas (idiomas): " +
                      ", ".join(str(qid) for qid, _ in expected_dups))

    if needs_variant:
        report.append("[WARN] IDs 11–15 sem variant explícito: " +
                      ", ".join(map(str, needs_variant)))

    if problematic_dups:
        report.append("[ERROR] Duplicações problemáticas:")
        for qid, variants in problematic_dups:
            report.append(f"  - ID {qid}: variants={variants}")

    if structure_errors:
        report.append("[ERROR] Problemas estruturais:")
        report.extend("  " + e for e in structure_errors)
    else:
        report.append("[OK] Estrutura: options único + A–D presentes.")

    ok = (not missing) and (not problematic_dups) and (not structure_errors)
    return ok, report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--file",
        default="vestibukar_2025_clean.txt.txt",
        help="Arquivo a validar"
    )
    args = ap.parse_args()

    ok, report = validate_file(args.file)
    print("\n".join(report))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
