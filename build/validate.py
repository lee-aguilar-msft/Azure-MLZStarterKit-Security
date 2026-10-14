#!/usr/bin/env python3
"""Lightweight ARM validator: JSON parse, parameters()/variables() reference existence, balanced
brackets in expression strings, and nested-deployment parameter wiring against the referenced template.
Not a substitute for `az deployment validate`, but catches the common authoring mistakes offline."""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
errors, warnings = [], []

TEMPLATES = {
    "solution.json": os.path.join(ROOT, "solution.json"),
    "tier3.json": os.path.join(ROOT, "templates", "tier3.json"),
    "ad-entra-vms.json": os.path.join(ROOT, "templates", "ad-entra-vms.json"),
    "security-lab.json": os.path.join(ROOT, "templates", "security-lab.json"),
    "arc-private-link.json": os.path.join(ROOT, "templates", "arc-private-link.json"),
    "cspm-coverage.json": os.path.join(ROOT, "templates", "cspm-coverage.json"),
}

def all_strings(o):
    if isinstance(o, str): yield o
    elif isinstance(o, dict):
        for v in o.values(): yield from all_strings(v)
    elif isinstance(o, list):
        for v in o: yield from all_strings(v)

def check_brackets(name, o):
    for sidx, s in enumerate(all_strings(o)):
        if s.startswith("[") and s.endswith("]") and not s.startswith("[["):
            depth = 0; inq = False
            for ch in s:
                if ch == "'" : inq = not inq
                elif not inq and ch in "([": depth += 1
                elif not inq and ch in ")]": depth -= 1
                if depth < 0: errors.append(f"{name}: unbalanced ) or ] in: {s[:80]}"); break
            if depth != 0: errors.append(f"{name}: unbalanced brackets ({depth}) in: {s[:80]}")

def check_refs(name, tmpl):
    params = set(tmpl.get("parameters", {}).keys())
    vars_ = set(tmpl.get("variables", {}).keys())
    blob = json.dumps(tmpl)
    for m in re.finditer(r"parameters\('([^']+)'\)", blob):
        if m.group(1) not in params:
            errors.append(f"{name}: parameters('{m.group(1)}') referenced but not declared")
    for m in re.finditer(r"variables\('([^']+)'\)", blob):
        if m.group(1) not in vars_:
            errors.append(f"{name}: variables('{m.group(1)}') referenced but not declared")

def check_nested(name, tmpl):
    """For deployments that templateLink to one of our local templates, confirm every passed parameter
    exists in that template and every required (no default) template param is passed."""
    link_map = {"templates/tier3.json": "tier3.json", "templates/ad-entra-vms.json": "ad-entra-vms.json",
                "templates/security-lab.json": "security-lab.json", "templates/arc-private-link.json": "arc-private-link.json",
                "templates/cspm-coverage.json": "cspm-coverage.json"}
    for r in tmpl.get("resources", []):
        if not r.get("type", "").endswith("deployments"): continue
        props = r.get("properties", {})
        link = props.get("templateLink", {})
        uri = link.get("uri", "") if isinstance(link, dict) else ""
        target = next((v for k, v in link_map.items() if k in uri), None)
        if not target: continue
        tgt = json.load(open(TEMPLATES[target]))
        tparams = tgt.get("parameters", {})
        passed = set(props.get("parameters", {}).keys())
        for pk in passed:
            if pk not in tparams:
                errors.append(f"{name} -> {target}: passes param '{pk}' not declared in target")
        for pk, spec in tparams.items():
            if "defaultValue" not in spec and pk not in passed:
                errors.append(f"{name} -> {target}: required param '{pk}' not passed")

loaded = {}
for name, path in TEMPLATES.items():
    try:
        loaded[name] = json.load(open(path))
    except Exception as e:
        errors.append(f"{name}: JSON parse failed: {e}")

# Upstream templates (tier3, cspm) contain nested inline templates with their own parameter scopes,
# which a flat regex scan can't tell apart — only ref-check the flat templates this kit authors.
AUTHORED = {"solution.json", "ad-entra-vms.json", "security-lab.json", "arc-private-link.json"}
for name, tmpl in loaded.items():
    check_brackets(name, tmpl)
    if name in AUTHORED:
        check_refs(name, tmpl)

if "solution.json" in loaded:
    check_nested("solution.json", loaded["solution.json"])

print("=== validation ===")
for w in warnings: print("WARN:", w)
for e in errors: print("ERROR:", e)
print(f"{len(errors)} error(s), {len(warnings)} warning(s)")
sys.exit(1 if errors else 0)
