#!/usr/bin/env python3
"""Extract candidate taint sources from a Fraunhofer CPG JSON export."""

import csv
import json
import os
import re
from collections import defaultdict, deque
from pathlib import Path

import yaml

from env_utils import env_optional_int, env_optional_path, env_path, env_str, load_env


DEFAULT_CONFIG_PATH = Path(__file__).parent / "config" / "candidate_source_rules.yml"


def code_of(node):
    return node.get("properties", {}).get("code") or ""


def prop(node, name, default=None):
    return node.get("properties", {}).get(name, default)


def has_any_label(node, labels):
    return bool(set(node.get("labels", ())) & labels)


def compact(value, limit=220):
    if value is None:
        return None
    value = " ".join(str(value).split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


def first_string_literal(text):
    match = re.search(r"""['"]([^'"]+)['"]""", text or "")
    return match.group(1) if match else None


def load_rule_config(path):
    with path.open(encoding="utf-8") as source:
        return yaml.safe_load(source)


def configured_languages(config):
    return set(config.get("languages", {}).keys())


def detected_languages(cpg, config):
    found = set()
    languages = config.get("languages", {})
    for node in cpg.get("nodes", []):
        labels = set(node.get("labels", ()))
        name = str(prop(node, "name", "") or "")
        label_text = " ".join(labels)
        text = f"{label_text} {name}".lower()
        for language, language_config in languages.items():
            keywords = language_config.get("detection", {}).get(
                "language_label_keywords", []
            )
            if any(keyword.lower() in text for keyword in keywords):
                found.add(language)

    if found:
        return found

    for node in cpg.get("nodes", []):
        artifact = str(prop(node, "artifact", "") or "")
        for language, language_config in languages.items():
            extensions = language_config.get("detection", {}).get(
                "artifact_extensions", []
            )
            if any(artifact.endswith(extension) for extension in extensions):
                found.add(language)
    return found


def selected_languages(cpg, requested, config):
    languages = configured_languages(config)
    if requested == "all":
        return languages
    if requested != "auto":
        if requested not in languages:
            available = ", ".join(sorted(languages))
            raise SystemExit(f"Unknown language {requested!r}. Configured: {available}")
        return {requested}
    return detected_languages(cpg, config) or languages


def detail_value(rule, code):
    detail = rule.get("detail")
    if detail == "first_string_literal":
        return first_string_literal(code)
    return detail


def regex_matches(rule, code):
    pattern = rule.get("code_regex")
    if not pattern:
        return True
    mode = rule.get("regex_mode", "search")
    if mode == "match":
        return re.match(pattern, code) is not None
    return re.search(pattern, code) is not None


def list_condition_matches(values, candidate, operator):
    values = values or []
    if not values:
        return True
    if operator == "equals":
        return candidate in values
    if operator == "prefix":
        return any(candidate.startswith(value) for value in values)
    if operator == "suffix":
        return any(candidate.endswith(value) for value in values)
    raise ValueError(f"Unknown list condition operator: {operator}")


def any_named_condition_matches(rule, candidate, conditions):
    present = [(key, operator) for key, operator in conditions if rule.get(key)]
    if not present:
        return True
    return any(
        list_condition_matches(rule.get(key), candidate, operator)
        for key, operator in present
    )


def rule_matches(rule, code, name, normalized, labels):
    labels_any = set(rule.get("node_labels_any", []))
    if labels_any and not labels_any.intersection(labels):
        return False

    if rule.get("any"):
        return any(rule_matches(part, code, name, normalized, labels) for part in rule["any"])

    if not regex_matches(rule, code):
        return False

    if not any_named_condition_matches(rule, name, (
        ("name_equals_any", "equals"),
        ("name_suffix_any", "suffix"),
    )):
        return False
    if not any_named_condition_matches(rule, normalized, (
        ("normalized_equals_any", "equals"),
        ("normalized_prefix_any", "prefix"),
        ("normalized_suffix_any", "suffix"),
    )):
        return False
    return True


def source_rules(node, languages, config, include_low_confidence=False):
    """Return zero or more source classifications for a node."""
    cpg_config = config.get("cpg", {})
    source_labels = set(cpg_config.get("source_node_labels", []))
    if source_labels and not has_any_label(node, source_labels):
        return []

    code = code_of(node)
    if not code:
        return []
    if cpg_config.get("skip_multiline_code", True) and "\n" in code:
        return []

    name = prop(node, "name", "") or ""
    labels = set(node.get("labels", ()))
    normalized = code.replace(" ", "")
    findings = []

    for language in sorted(languages):
        language_config = config.get("languages", {}).get(language, {})
        for rule in language_config.get("rules", []):
            if rule.get("low_confidence") and not include_low_confidence:
                continue
            if not rule_matches(rule, code, name, normalized, labels):
                continue
            findings.append({
                "language": language,
                "ruleId": rule.get("id"),
                "kind": rule["kind"],
                "detail": detail_value(rule, code),
                "confidence": rule.get("confidence", "high"),
                "reason": rule.get("reason"),
            })

    return findings


def build_indexes(edges):
    incoming = defaultdict(list)
    outgoing = defaultdict(list)
    by_type_out = defaultdict(lambda: defaultdict(list))
    for edge in edges:
        incoming[edge["endNode"]].append(edge)
        outgoing[edge["startNode"]].append(edge)
        by_type_out[edge["type"]][edge["startNode"]].append(edge)
    return incoming, outgoing, by_type_out


def enclosing_function(node, functions):
    artifact = prop(node, "artifact")
    line = prop(node, "startLine")
    if artifact is None or line is None or line < 0:
        return None

    best = None
    best_span = None
    for function in functions:
        if prop(function, "artifact") != artifact:
            continue
        start = prop(function, "startLine")
        end = prop(function, "endLine")
        if start is None or end is None or start < 0 or end < 0:
            continue
        if start <= line <= end:
            span = end - start
            if best is None or span < best_span:
                best = function
                best_span = span
    if not best:
        return None
    return {
        "id": best["id"],
        "name": prop(best, "name"),
        "startLine": prop(best, "startLine"),
        "endLine": prop(best, "endLine"),
    }


def edge_matches_config(edge, edge_config):
    if edge["type"] != edge_config.get("type"):
        return False
    filters = edge_config.get("property_filters", {})
    properties = edge.get("properties", {})
    return all(properties.get(key) == value for key, value in filters.items())


def dfg_context(start_id, nodes_by_id, outgoing, max_depth, config):
    if max_depth <= 0:
        return []

    dataflow_edges = config.get("cpg", {}).get("dataflow", {}).get("edges", [])
    results = []
    queue = deque([(start_id, 0)])
    seen = {start_id}
    while queue:
        node_id, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for edge in outgoing.get(node_id, ()):
            if not any(edge_matches_config(edge, item) for item in dataflow_edges):
                continue
            target_id = edge["endNode"]
            if target_id in seen:
                continue
            seen.add(target_id)
            target = nodes_by_id.get(target_id)
            if not target:
                continue
            results.append({
                "depth": depth + 1,
                "edgeType": edge["type"],
                "nodeId": target_id,
                "labels": target.get("labels", []),
                "code": compact(code_of(target), 140),
                "name": prop(target, "name"),
                "line": prop(target, "startLine"),
            })
            queue.append((target_id, depth + 1))
    return results


def assignment_lhs(node_id, nodes_by_id, incoming, by_type_out, config):
    assignment_config = config.get("cpg", {}).get("assignment", {})
    rhs_edge = assignment_config.get("rhs_edge", "RHS")
    lhs_edge = assignment_config.get("lhs_edge", "LHS")
    for edge in incoming.get(node_id, ()):
        if edge["type"] != rhs_edge:
            continue
        assign_id = edge["startNode"]
        lhs_edges = by_type_out[lhs_edge].get(assign_id, [])
        if not lhs_edges:
            return None
        lhs = nodes_by_id.get(lhs_edges[0]["endNode"])
        if not lhs:
            return None
        return {
            "nodeId": lhs["id"],
            "name": prop(lhs, "name"),
            "code": compact(code_of(lhs), 120),
            "line": prop(lhs, "startLine"),
        }
    return None


def related_uses(assigned, function, nodes, nodes_by_id, incoming, config):
    if not assigned or not assigned.get("name") or not function:
        return []

    related_config = config.get("cpg", {}).get("related_uses", {})
    limit = related_config.get("limit", 30)
    reference_label = related_config.get("reference_label", "Reference")
    parent_edges = set(related_config.get("parent_edges", []))
    name = assigned["name"]
    start = function.get("startLine")
    end = function.get("endLine")
    if start is None or end is None:
        return []

    uses = []
    for node in nodes:
        if node["id"] == assigned.get("nodeId"):
            continue
        if reference_label not in node.get("labels", ()):
            continue
        if prop(node, "name") != name:
            continue
        line = prop(node, "startLine")
        if line is None or not (start <= line <= end):
            continue

        parents = []
        for edge in incoming.get(node["id"], ()):
            if parent_edges and edge["type"] not in parent_edges:
                continue
            parent = nodes_by_id.get(edge["startNode"])
            if not parent:
                continue
            parents.append({
                "relation": edge["type"],
                "nodeId": parent["id"],
                "labels": parent.get("labels", []),
                "name": prop(parent, "name"),
                "code": compact(code_of(parent), 180),
                "line": prop(parent, "startLine"),
            })

        uses.append({
            "nodeId": node["id"],
            "line": line,
            "code": compact(code_of(node), 120),
            "parents": parents[:5],
        })
        if len(uses) >= limit:
            break

    return uses


def extract(cpg, languages, config, dfg_depth=None, include_low_confidence=False):
    nodes = cpg["nodes"]
    edges = cpg["edges"]
    if dfg_depth is None:
        dfg_depth = config.get("cpg", {}).get("dataflow", {}).get("max_depth_default", 2)
    nodes_by_id = {node["id"]: node for node in nodes}
    incoming, outgoing, by_type_out = build_indexes(edges)
    function_labels = set(config.get("cpg", {}).get("function_labels_any", []))
    functions = [
        node for node in nodes
        if function_labels & set(node.get("labels", ()))
    ]

    findings = []
    for node in nodes:
        for match in source_rules(node, languages, config, include_low_confidence):
            assigned = assignment_lhs(node["id"], nodes_by_id, incoming, by_type_out, config)
            function = enclosing_function(node, functions)
            finding = {
                "nodeId": node["id"],
                "language": match["language"],
                "ruleId": match.get("ruleId"),
                "kind": match["kind"],
                "detail": match["detail"],
                "confidence": match["confidence"],
                "reason": match["reason"],
                "artifact": prop(node, "artifact"),
                "startLine": prop(node, "startLine"),
                "endLine": prop(node, "endLine"),
                "labels": node.get("labels", []),
                "name": prop(node, "name"),
                "fullName": prop(node, "fullName"),
                "code": code_of(node),
                "assignedTo": assigned,
                "enclosingFunction": function,
                "dataflow": dfg_context(node["id"], nodes_by_id, outgoing, dfg_depth, config),
                "relatedUses": related_uses(assigned, function, nodes, nodes_by_id, incoming, config),
            }
            findings.append(finding)

    findings.sort(key=lambda item: (
        item.get("artifact") or "",
        item.get("startLine") if item.get("startLine") is not None else 10**9,
        item["nodeId"],
        item["kind"],
    ))
    return findings


def write_csv(path, findings):
    fields = [
        "nodeId",
        "ruleId",
        "kind",
        "language",
        "detail",
        "confidence",
        "artifact",
        "startLine",
        "endLine",
        "function",
        "assignedTo",
        "code",
        "reason",
    ]
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for item in findings:
            writer.writerow({
                "nodeId": item["nodeId"],
                "ruleId": item.get("ruleId"),
                "kind": item["kind"],
                "language": item["language"],
                "detail": item["detail"],
                "confidence": item["confidence"],
                "artifact": item["artifact"],
                "startLine": item["startLine"],
                "endLine": item["endLine"],
                "function": (item.get("enclosingFunction") or {}).get("name"),
                "assignedTo": (item.get("assignedTo") or {}).get("code"),
                "code": item["code"],
                "reason": item["reason"],
            })


def main():
    base_dir = Path(__file__).resolve().parent
    env_file = os.getenv(
        "SOURCES_CANDIDATE_ENV_FILE",
        str(base_dir / "config" / "sources_candidate_finder.env"),
    )
    load_env(env_file)

    cpg = env_path("SOURCES_CANDIDATE_CPG")
    out = env_optional_path("SOURCES_CANDIDATE_OUT")
    config_path = env_path("SOURCES_CANDIDATE_CONFIG")
    output_format = env_str("SOURCES_CANDIDATE_FORMAT")
    if output_format not in {"json", "csv"}:
        raise SystemExit("SOURCES_CANDIDATE_FORMAT must be json or csv")
    dfg_depth = env_optional_int("SOURCES_CANDIDATE_DFG_DEPTH")
    language = env_str("SOURCES_CANDIDATE_LANGUAGE")
    include_low_confidence = env_str("SOURCES_CANDIDATE_INCLUDE_LOW_CONFIDENCE").lower() == "true"

    if dfg_depth is not None and dfg_depth < 0:
        raise SystemExit("--dfg-depth must be zero or greater")

    config = load_rule_config(config_path)
    with cpg.open(encoding="utf-8") as source:
        cpg_payload = json.load(source)

    languages = selected_languages(cpg_payload, language, config)

    findings = extract(
        cpg_payload,
        languages=languages,
        config=config,
        dfg_depth=dfg_depth,
        include_low_confidence=include_low_confidence,
    )

    payload = {
        "sourceFile": str(cpg),
        "configFile": str(config_path),
        "ruleLanguages": sorted(languages),
        "candidateSourceCount": len(findings),
        "candidateSources": findings,
    }

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        if output_format == "json":
            out.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        else:
            write_csv(out, findings)

    print(f"candidate sources: {len(findings)}")
    for item in findings[:20]:
        location = f"{item.get('artifact')}:{item.get('startLine')}"
        assigned = item.get("assignedTo") or {}
        suffix = f" -> {assigned.get('code')}" if assigned else ""
        detail = f" [{item['detail']}]" if item.get("detail") else ""
        print(f"- {item['language']}:{item['kind']}{detail} {location} {item['code']}{suffix}")
    if len(findings) > 20:
        print(f"... {len(findings) - 20} more")


if __name__ == "__main__":
    main()




# python3 sources_candidate_finder.py data/openstack__kolla__2a4a8fce31c1.json -o data/openstack__kolla__2a4a8fce31c1.sources.json
