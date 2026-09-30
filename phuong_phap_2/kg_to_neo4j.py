"""Nạp out/kg.json trực tiếp vào Neo4j. Chạy lại nhiều lần không bị nhân đôi dữ liệu.

Cài driver một lần:  pip install neo4j
Chạy:
  python kg_to_neo4j.py --kg out/kg.json --uri bolt://localhost:7687 --user neo4j --password MAT_KHAU
Thêm --wipe để xóa sạch graph cũ trước khi nạp.
Với AuraDB dùng uri dạng neo4j+s://xxxxxxxx.databases.neo4j.io
"""
import argparse, collections, hashlib, json, re

from neo4j import GraphDatabase


def label(t):
    return "".join(p.capitalize() for p in re.split(r"[^A-Za-z0-9]+", t or "") if p) or "Entity"


def rel(r):
    return re.sub(r"[^A-Za-z0-9]+", "_", r).upper()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kg", default="out/kg.json")
    ap.add_argument("--uri", default="bolt://localhost:7687")
    ap.add_argument("--user", default="neo4j")
    ap.add_argument("--password", required=True)
    ap.add_argument("--database", default=None, help="mặc định dùng database mặc định của server")
    ap.add_argument("--wipe", action="store_true")
    a = ap.parse_args()

    kg = json.load(open(a.kg, encoding="utf-8"))
    lab = {n["id"]: label(n["type"]) for n in kg["nodes"]}

    nodes_by_label = collections.defaultdict(list)
    for n in kg["nodes"]:
        nodes_by_label[lab[n["id"]]].append({"id": n["id"], "props": {k: v for k, v in n.items() if v is not None}})

    groups = collections.defaultdict(list)
    skipped = 0
    for t in kg["triples"]:
        if t["h"] not in lab or t["t"] not in lab:
            skipped += 1
            continue
        props = {k: v for k, v in t.items() if k not in ("h", "r", "t") and v is not None}
        key = hashlib.md5(json.dumps(t, sort_keys=True).encode()).hexdigest()
        groups[(rel(t["r"]), lab[t["h"]], lab[t["t"]])].append({"h": t["h"], "t": t["t"], "key": key, "props": props})

    driver = GraphDatabase.driver(a.uri, auth=(a.user, a.password))
    with driver.session(database=a.database) as s:
        if a.wipe:
            s.run("MATCH (n) DETACH DELETE n")
        for L, rows in nodes_by_label.items():
            s.run(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{L}) REQUIRE n.id IS UNIQUE")
            s.run(f"UNWIND $rows AS r MERGE (n:{L} {{id: r.id}}) SET n += r.props", rows=rows)
        for (R, HL, TL), rows in groups.items():
            s.run(f"UNWIND $rows AS r MATCH (a:{HL} {{id: r.h}}), (b:{TL} {{id: r.t}}) "
                  f"MERGE (a)-[e:{R} {{key: r.key}}]->(b) SET e += r.props", rows=rows)
        c = s.run("MATCH (n) RETURN count(n) AS n").single()["n"]
        e = s.run("MATCH ()-[r]->() RETURN count(r) AS n").single()["n"]
    driver.close()
    print(f"xong. Trong Neo4j hiện có {c} node, {e} cạnh" + (f" (bỏ {skipped} cạnh thiếu node)" if skipped else ""))


if __name__ == "__main__":
    main()
