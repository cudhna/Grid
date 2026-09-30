"""Dựng KG từ report_1.json bằng khớp từ điển với enterprise-attack.json (không dùng model).

Chạy:
  python dict_kg.py --attack enterprise-attack.json --report report_1.canonical.json --out . --only-ttp

--only-ttp: chỉ giữ node tactic/technique, bỏ qua node malware/tool/intrusion-set/campaign.
  Phù hợp với phạm vi nghiên cứu hiện tại (chỉ Tactic + Technique).
"""
import argparse, collections, json, os, re, sys

try:    # console Windows mac dinh la cp1252, khong in duoc tieng Viet
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ENTITY_TYPES = {"malware", "tool", "intrusion-set", "campaign"}
TTP_TYPES = {"attack-pattern", "x-mitre-tactic"}


def ext_id(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")


def walk(node, chunk_idx=None):
    """Đi đệ quy, lấy mọi dict có 'id' và 'procedure' (kèm chỉ số chunk nếu report là list theo chunk)."""
    if isinstance(node, dict):
        if "id" in node and "procedure" in node:
            yield chunk_idx, node
        for v in node.values():
            yield from walk(v, chunk_idx)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk(v, i if chunk_idx is None else chunk_idx)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--out", default="out")
    ap.add_argument("--only-ttp", action="store_true",
                    help="chi giu node tactic/technique, bo qua malware/tool/intrusion-set/campaign")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    keep_types = TTP_TYPES if a.only_ttp else None

    objs = json.load(open(a.attack, encoding="utf-8"))["objects"]
    objs = [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_stix = {o["id"]: o for o in objs}
    tech_by_ext = {ext_id(o): o for o in objs if o["type"] == "attack-pattern" and ext_id(o)}
    tactic_by_short = {o["x_mitre_shortname"]: o for o in objs if o["type"] == "x-mitre-tactic"}

    # từ điển alias -> danh sách stix id
    alias = collections.defaultdict(set)
    for o in objs:
        if o["type"] in ENTITY_TYPES:
            for n in [o["name"]] + o.get("x_mitre_aliases", []):
                alias[n].add(o["id"])
    names = sorted(alias, key=len, reverse=True)
    # tên ngắn (<=4 ký tự) khớp phân biệt hoa/thường để bớt nhiễu
    def rx(ns, flags):
        if not ns:
            return None
        return re.compile(r"(?<![\w])(?:" + "|".join(map(re.escape, ns)) + r")(?![\w])", flags)
    rx_long = rx([n for n in names if len(n) > 4], re.I)
    rx_short = rx([n for n in names if len(n) <= 4], 0)
    lower_map = {n.lower(): n for n in names}

    def find(text):
        hits = []
        for r in (rx_long, rx_short):
            if r:
                for m in r.finditer(text):
                    key = m.group(0)
                    canon = key if key in alias else lower_map.get(key.lower())
                    if canon:
                        hits.append((canon, m.start(), m.end()))
        return hits

    # relationship "uses": entity -> attack-pattern
    uses = collections.defaultdict(set)
    for o in objs:
        if o["type"] == "relationship" and o["relationship_type"] == "uses":
            uses[o["source_ref"]].add(o["target_ref"])

    report = json.load(open(a.report, encoding="utf-8"))
    nodes, triples, flags = {}, [], []

    def add_node(nid, typ, name, **kw):
        nodes.setdefault(nid, {"id": nid, "type": typ, "name": name, **kw})

    seen_tech = set()
    for ci, t in walk(report):
        tid, proc = t["id"], (t.get("procedure") or "").strip()
        tech = tech_by_ext.get(tid)
        if tid not in seen_tech:
            seen_tech.add(tid)
            if not tech:
                flags.append({"technique": tid, "flag": "id_not_in_attack_or_deprecated"})
            else:
                if tech["name"].lower() != (t.get("name") or "").lower():
                    flags.append({"technique": tid, "flag": "name_mismatch",
                                  "report": t.get("name"), "attack": tech["name"]})
                add_node(tid, "attack-pattern", tech["name"], external_id=tid, source="attack")
                for kc in tech.get("kill_chain_phases", []):
                    tac = tactic_by_short.get(kc["phase_name"])
                    if tac:
                        add_node(ext_id(tac), "x-mitre-tactic", tac["name"], external_id=ext_id(tac), source="attack")
                        triples.append({"h": tid, "r": "part_of", "t": ext_id(tac), "source": "attack"})
        if not proc:
            continue
        for canon, s, e in find(proc):
            for sid in alias[canon]:
                o = by_stix[sid]
                eid = ext_id(o) or sid
                if keep_types and o["type"] not in keep_types:
                    continue
                add_node(eid, o["type"], o["name"], external_id=ext_id(o), source="attack",
                         ambiguous=len(alias[canon]) > 1)
                # cạnh đến từ báo cáo: thực thể xuất hiện trong procedure của technique
                triples.append({"h": eid, "r": "mentioned_in_procedure_of", "t": tid, "source": "report",
                                "chunk": ci, "span": [s, e], "matched": proc[s:e]})
                # cạnh đến từ ATT&CK, đối chiếu với báo cáo
                if tech and tech["id"] in uses[sid]:
                    triples.append({"h": eid, "r": "uses", "t": tid, "source": "attack",
                                    "confirmed_by_report": True})

    # loại cạnh trùng
    uniq = {json.dumps(x, sort_keys=True): x for x in triples}
    triples = list(uniq.values())
    json.dump({"nodes": list(nodes.values()), "triples": triples},
              open(os.path.join(a.out, "kg.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    json.dump(flags, open(os.path.join(a.out, "flags.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    n_tech = len(seen_tech)
    n_proc = sum(1 for _, t in walk(report) if (t.get("procedure") or "").strip())
    print(f"technique khác nhau: {n_tech}; mục có procedure: {n_proc}")
    print(f"nodes: {len(nodes)}; triples: {len(triples)}; flags: {len(flags)}")
    ent = [n for n in nodes.values() if n["type"] in ENTITY_TYPES]
    print("entity khớp được:", [(n["name"], n["external_id"]) for n in ent] or "không có")


if __name__ == "__main__":
    main()
