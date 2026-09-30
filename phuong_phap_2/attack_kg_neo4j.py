"""Nạp MITRE ATT&CK (lớp nền) vào Neo4j, rồi phủ dữ liệu từ báo cáo (kg.json) lên trên.

Lớp nền có 2 nguồn:
  --attack  enterprise-attack.json : nạp TOÀN BỘ ATT&CK (25.639 object, đồ thị rất rộng)
  --scoped  kg_base_scoped.json   : nạp lớp nền ĐÃ THU HẸP về phạm vi malware loader,
                                   do scope_loader.py sinh ra. Đây là lựa chọn mặc định
                                   cho phạm vi nghiên cứu hiện tại (chỉ Tactic + Technique).

Chạy lần đầu (xóa graph cũ):
  python attack_kg_neo4j.py --scoped kg_base_scoped.json --kg kg.json --report-name report_1 --password MAT_KHAU --wipe
Chạy lại khi có kg.json mới (không --wipe, không bị nhân đôi):
  python attack_kg_neo4j.py --scoped kg_base_scoped.json --kg kg.json --report-name report_2 --password MAT_KHAU
Bỏ --kg nếu chỉ muốn nạp lớp nền.

Tầng GRID (out/kg_full.json sinh bởi out/build_kg_full.py) nạp chung một lệnh:
  python attack_kg_neo4j.py --scoped kg_base_scoped.json --kg ..\\out\\kg_full.json --report-name report_1 --password MAT_KHAU
Cạnh trong kg_full.json phân biệt bằng `inferred_by`:
  "code" -> cạnh USES suy ra bằng code (không phải model trích)
  "grid" -> triple do model GRID trích (luôn kèm evidence / evidence_status)
Node/cạnh lớp GRID có `source='grid'`, `layer='grid'`;
triple thiếu câu bằng chứng vẫn được nạp, đánh dấu `evidence_status`.
Kiểm tra số liệu trước khi nạp (không cần Neo4j): thêm --dry-run.
"""
import argparse, collections, hashlib, json, re, sys

from neo4j import GraphDatabase

try:    # console Windows mac dinh la cp1252
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SKIP = {"relationship", "identity", "marking-definition", "x-mitre-collection", "x-mitre-matrix",
        "extension-definition"}

# Thu tu uu tien khi mot node xuat hien o ca 3 lop.
# Node da nam trong lop nen giu layer='base' (khong ghi de thong tin lop nen);
# `layers` ghi lai node do da duoc lop bao cao / GRID cham vao.
LAYER_RANK = ("base", "grid", "report")


def label(t):
    return "".join(p.capitalize() for p in re.split(r"[^A-Za-z0-9]+", t or "") if p) or "Entity"


def rel(r):
    return re.sub(r"[^A-Za-z0-9]+", "_", r).upper()


def safe_props(d, drop=()):
    """Neo4j chi nhan primitive hoac list cua primitive.
    Dict (vd evidence_matched_words) -> chuoi JSON. Gia tri rong -> bo (khong ghi null)."""
    out = {}
    for k, v in d.items():
        if k in drop or v is None:
            continue
        if isinstance(v, (bool, int, float, str)):
            out[k] = v
        elif isinstance(v, dict):
            if v:
                out[k] = json.dumps(v, ensure_ascii=False)
        elif isinstance(v, (list, tuple, set)):
            items = [x for x in v if x is not None]
            if not items:
                continue
            if all(isinstance(x, (bool, int, float, str)) for x in items):
                out[k] = items
            else:
                out[k] = json.dumps(items, ensure_ascii=False)
        else:
            out[k] = str(v)
    return out


def node_layer(n, in_base):
    """Chon `layer` chinh + danh sach `layers` cho node cua kg.json / kg_full.json."""
    srcs = list(n.get("sources") or [])
    if n.get("source") and n["source"] not in srcs:
        srcs.append(n["source"])
    layers = {s for s in srcs if s in LAYER_RANK}
    if in_base:
        layers.add("base")
    primary = n.get("layer")
    for cand in LAYER_RANK:
        if cand in layers:
            primary = cand
            break
    else:
        primary = primary or "report"
    return primary or "report", sorted(layers)


def attack_ref(o):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id"), r.get("url")
    return None, None


def batches(rows, n=1000):
    for i in range(0, len(rows), n):
        yield rows[i:i + n]


def load_base_attack(path):
    """Lớp nền từ bundle STIX đầy đủ (không lọc phạm vi)."""
    objs = json.load(open(path, encoding="utf-8"))["objects"]
    ok = [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    ref = {}                      # stix id -> (label, id)
    nodes = collections.defaultdict(list)
    for o in ok:
        if o["type"] in SKIP:
            continue
        eid, url = attack_ref(o)
        nid = eid or o["id"]
        L = label(o["type"])
        ref[o["id"]] = (L, nid)
        props = {"id": nid, "type": o["type"], "name": o.get("name"), "external_id": eid, "stix_id": o["id"],
                 "url": url, "description": (o.get("description") or "")[:400], "source": "attack", "layer": "base"}
        nodes[L].append({"id": nid, "props": {k: v for k, v in props.items() if v is not None}})

    groups = collections.defaultdict(list)     # (REL, hlabel, tlabel) -> rows
    for o in ok:
        if o["type"] == "relationship" and o["source_ref"] in ref and o["target_ref"] in ref:
            (hl, h), (tl, t) = ref[o["source_ref"]], ref[o["target_ref"]]
            groups[(rel(o["relationship_type"]), hl, tl)].append(
                {"h": h, "t": t, "key": o["id"], "props": {"source": "attack", "layer": "base"}})
    tactic = {o["x_mitre_shortname"]: o for o in ok if o["type"] == "x-mitre-tactic"}
    for o in ok:
        if o["type"] == "attack-pattern" and o["id"] in ref:
            for kc in o.get("kill_chain_phases", []):
                tac = tactic.get(kc["phase_name"])
                if tac and tac["id"] in ref:
                    groups[("PART_OF", "AttackPattern", "XMitreTactic")].append(
                        {"h": ref[o["id"]][1], "t": ref[tac["id"]][1], "key": f"{o['id']}|{tac['id']}",
                         "props": {"source": "attack", "layer": "base"}})
    return nodes, groups, {"mode": "attack-full", "attack": path}


def load_base_scoped(path):
    """Lớp nền đã thu hẹp về phạm vi malware loader (output của scope_loader.py).

    Mỗi node giữ thuộc trường in_loader_scope (True = nằm trong định nghĩa phạm vi loader,
    False = chỉ xuất hiện vì báo cáo) và keep_reason (quy tắc nào giữ node đó).
    """
    data = json.load(open(path, encoding="utf-8"))
    nodes = collections.defaultdict(list)
    for n in data["nodes"]:
        L = label(n["type"])
        props = {k: v for k, v in n.items() if v is not None and k != "id"}
        nodes[L].append({"id": n["id"], "props": props})

    groups = collections.defaultdict(list)
    lab = {n["id"]: label(n["type"]) for n in data["nodes"]}
    for t in data["triples"]:
        if t["h"] not in lab or t["t"] not in lab:
            continue
        groups[(rel(t["r"]), lab[t["h"]], lab[t["t"]])].append(
            {"h": t["h"], "t": t["t"], "key": f"{t['h']}|{t['r']}|{t['t']}",
             "props": safe_props(t, drop=("h", "r", "t"))})
    return nodes, groups, {"mode": "scoped", "scoped": path, "meta": data.get("meta", {})}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", default=None,
                    help="enterprise-attack.json (nạp TOÀN BỘ ATT&CK) - dùng khi muốn đồ thị đầy đủ")
    ap.add_argument("--scoped", default="kg_base_scoped.json",
                    help="kg_base_scoped.json từ scope_loader.py - lớp nền đã thu hẹp (mặc định)")
    ap.add_argument("--kg", default=None,
                    help="kg.json tu dict_kg.py (lop report) HOAC out/kg_full.json (report + grid). "
                         "Bo qua neu chi nap lop nen.")
    ap.add_argument("--report-name", default="report_1")
    ap.add_argument("--uri", default="bolt://localhost:7687")
    ap.add_argument("--user", default="neo4j")
    ap.add_argument("--password", required=True)
    ap.add_argument("--database", default=None)
    ap.add_argument("--wipe", action="store_true")
    ap.add_argument("--dry-run", action="store_true",
                    help="không cần Neo4j: chỉ in số node/cạnh sẽ nạp (để kiểm tra trước)")
    a = ap.parse_args()

    # ---------- 1. lớp nền ----------
    import os
    if a.attack:
        nodes, groups, info = load_base_attack(a.attack)
    elif os.path.exists(a.scoped):
        nodes, groups, info = load_base_scoped(a.scoped)
    else:
        ap.error("khong tim thay %s. Hay chay: python scope_loader.py ..." % a.scoped)

    n_node = sum(len(v) for v in nodes.values())
    n_edge = sum(len(v) for v in groups.values())
    if a.dry_run:
        print(f"[dry-run] lop nen [{info['mode']}]: {n_node} node, {n_edge} canh")
        for L in sorted(nodes):
            print(f"    {L:20s} {len(nodes[L]):6d}")
        for key in sorted(groups):
            print(f"    {key[0]:18s} {key[1]} -> {key[2]}: {len(groups[key])}")
        if a.kg:
            kg = json.load(open(a.kg, encoding="utf-8"))
            lab = {n["id"]: label(n["type"]) for n in kg["nodes"]}
            base_ids = {r["id"] for rows in nodes.values() for r in rows}
            print(f"[dry-run] lop bao cao: {len(kg['nodes'])} node, {len(kg['triples'])} triple")
            new_nodes = [n["id"] for n in kg["nodes"] if n["id"] not in base_ids]
            print(f"    technique/tactic co san trong nen: {len(kg['nodes']) - len(new_nodes)}")
            print(f"    node moi (ngoai pham vi loader):   {len(new_nodes)} -> {new_nodes}")
            by_src = collections.Counter(t.get("source") or "report" for t in kg["triples"])
            by_inf = collections.Counter(t.get("inferred_by") for t in kg["triples"]
                                         if t.get("source") == "grid")
            print(f"    triple theo source: {dict(by_src)}")
            if by_inf:
                print(f"    triple grid theo inferred_by: {dict(by_inf)}")
            lay = collections.Counter(node_layer(n, n["id"] in base_ids)[0] for n in kg["nodes"])
            print(f"    node theo layer se nap: {dict(lay)}")
            missing = [t for t in kg["triples"] if t["h"] not in lab or t["t"] not in lab]
            print(f"    bo qua (dau canh khong co node): {len(missing)}")
        return

    driver = GraphDatabase.driver(a.uri, auth=(a.user, a.password))
    with driver.session(database=a.database) as s:
        if a.wipe:
            s.run("MATCH (n) DETACH DELETE n")
        for L, rows in nodes.items():
            s.run(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{L}) REQUIRE n.id IS UNIQUE")
            for b in batches(rows):
                s.run(f"UNWIND $rows AS r MERGE (n:{L} {{id: r.id}}) SET n += r.props", rows=b)
        for (R, HL, TL), rows in groups.items():
            for b in batches(rows):
                s.run(f"UNWIND $rows AS r MATCH (a:{HL} {{id: r.h}}), (b:{TL} {{id: r.t}}) "
                      f"MERGE (a)-[e:{R} {{key: r.key}}]->(b) SET e += r.props", rows=b)
        print(f"lớp nền [{info['mode']}]: {sum(len(v) for v in nodes.values())} node, "
              f"{sum(len(v) for v in groups.values())} cạnh")

        # ---------- 2. lớp báo cáo phủ lên trên ----------
        if a.kg:
            kg = json.load(open(a.kg, encoding="utf-8"))
            lab = {n["id"]: label(n["type"]) for n in kg["nodes"]}
            # node trong lớp nền (đã biết có nằm trong phạm vi loader hay không)
            base_props = {r["id"]: r["props"] for rows in nodes.values() for r in rows}
            s.run("CREATE CONSTRAINT IF NOT EXISTS FOR (n:Report) REQUIRE n.id IS UNIQUE")
            s.run("MERGE (r:Report {id: $n}) SET r.name = $n, r.layer = 'report', r.type = 'report'", n=a.report_name)
            for L in {lab[n["id"]] for n in kg["nodes"]}:
                s.run(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{L}) REQUIRE n.id IS UNIQUE")
                rows = []
                for n in kg["nodes"]:
                    if lab[n["id"]] != L:
                        continue
                    props = safe_props(n, drop=("source", "layer"))
                    base = base_props.get(n["id"])
                    # giữ cờ phạm vi từ lớp nền; node không có trong nền thì mặc định ngoài phạm vi
                    props["in_loader_scope"] = bool(base.get("in_loader_scope")) if base else False
                    if base and base.get("keep_reason"):
                        props["keep_reason"] = base["keep_reason"]
                    if base is None:
                        props["keep_reason"] = ["report"]
                    # node đã có trong lớp nền giữ layer='base'; node GRID mới -> 'grid';
                    # node mới hoàn toàn -> 'report'. `layers` ghi đủ các lớp đã chạm node.
                    primary, layers = node_layer(n, base is not None)
                    props["layer"] = primary
                    props["layers"] = layers
                    srcs = list(n.get("sources") or [])
                    if n.get("source") and n["source"] not in srcs:
                        srcs.append(n["source"])
                    props["source"] = srcs[0] if srcs else "report"
                    rows.append({"id": n["id"], "props": props})
                s.run(f"UNWIND $rows AS r MERGE (n:{L} {{id: r.id}}) SET n += r.props", rows=rows)
            obs = [{"id": n["id"]} for n in kg["nodes"] if n["type"] == "attack-pattern"]
            s.run("UNWIND $rows AS r MATCH (rep:Report {id: $n}), (t:AttackPattern {id: r.id}) "
                  "MERGE (rep)-[e:OBSERVES]->(t) SET e.source = 'report', e.layer = 'report'", rows=obs, n=a.report_name)
            new_edges = new_grid = 0
            for t in kg["triples"]:
                if t["h"] not in lab or t["t"] not in lab:
                    continue
                HL, TL = lab[t["h"]], lab[t["t"]]
                src = t.get("source") or "report"
                if src == "attack":
                    # cạnh ATT&CK có sẵn, chỉ đánh dấu báo cáo cũng xác nhận
                    # (kg_full.json chuan hoa nhãn qua cypher_rel() nên so khong phan biet hoa/thuong)
                    if t["r"].strip().lower() == "uses":
                        s.run(f"MATCH (a:{HL} {{id: $h}})-[e:USES]->(b:{TL} {{id: $t}}) "
                              f"SET e.confirmed_by_report = true, e.report = $n", h=t["h"], t=t["t"], n=a.report_name)
                    continue
                props = safe_props(t, drop=("h", "r", "t", "source", "layer"))
                props.update({"layer": "grid" if src == "grid" else "report",
                              "source": src, "report": a.report_name})
                key = hashlib.md5(json.dumps([a.report_name, t], sort_keys=True).encode()).hexdigest()
                s.run(f"MATCH (a:{HL} {{id: $h}}), (b:{TL} {{id: $t}}) MERGE (a)-[e:{rel(t['r'])} {{key: $k}}]->(b) "
                      f"SET e += $p", h=t["h"], t=t["t"], k=key, p=props)
                new_edges += 1
                if src == "grid":
                    new_grid += 1
            print(f"lớp báo cáo '{a.report_name}': {len(obs)} technique được quan sát, "
                  f"{new_edges} cạnh mới từ báo cáo"
                  + (f" (trong đó {new_grid} cạnh do GRID trích)" if new_grid else ""))
        c = s.run("MATCH (n) RETURN count(n) AS n").single()["n"]
        e = s.run("MATCH ()-[r]->() RETURN count(r) AS n").single()["n"]
    driver.close()
    print(f"xong. Neo4j hiện có {c} node, {e} cạnh")


if __name__ == "__main__":
    main()
