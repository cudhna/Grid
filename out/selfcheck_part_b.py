"""
KIEM TRA DUONG OI B2-B5 bang fixture TONG HOP trong thu muc TAM.

KHONG phai ket qua GRID that. Muc dich: chung minh code chay dung va cac bat bien
duoc giu:
  - id node khong trung
  - khong co canh tro toi node khong ton tai
  - nhan canh hop le cho Cypher
  - canh suy ra bang code (B3) tach rieng khoi canh model trich (B4)
  - khong xoa triple thieu bang chung, chi gan co
  - node khop duoc ATT&CK co external_id; node moi de trong external_id

Ket qua KHONG duoc ghi vao out/kg_full.json va KHONG duoc bao cao la so lieu that.

Chay:
    python out/selfcheck_part_b.py
"""
import collections
import json
import re
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_kg_full as B  # noqa: E402

tmp = Path(tempfile.mkdtemp(prefix="kgfix_"))
grid_raw = tmp / "grid_raw"
grid_raw.mkdir()

idx = B.load_attack_index(Path("phuong_phap_2/enterprise-attack.json"))
mimikatz = idx["software"].get("mimikatz") or idx["software_alias"].get("mimikatz")
print("trong bundle co Mimikatz:", bool(mimikatz),
      "| id dung:", mimikatz[0]["external_id"] if mimikatz else "-")

PROCS = [
    dict(procedure_id="proc_01", chunk=0, tactic="Impact", technique_id="T1486",
         technique_name="Data Encrypted for Impact", procedure_chars=139,
         technique_codes_in_text=[], grid_dir="proc_01_T1486",
         procedure="CyberLock ransomware uses Mimikatz by dumping credentials, "
                   "then encrypts the victim's files."),
    dict(procedure_id="proc_02", chunk=5, tactic="Execution", technique_id="T1059.001",
         technique_name="PowerShell", procedure_chars=120,
         technique_codes_in_text=["T1112"], grid_dir="proc_02_T1059.001",
         procedure="The operator uses PowerShell to change the registry key per T1112."),
    dict(procedure_id="proc_03", chunk=9, tactic="Execution", technique_id="T1027.009",
         technique_name="Embedded Payloads", procedure_chars=100,
         technique_codes_in_text=[], grid_dir="proc_03_T1027.009",
         procedure="An unrelated sentence with no known software at all."),
]
(grid_raw / "procedure_map.json").write_text(
    json.dumps({"source_report": "report_1.json", "count": len(PROCS), "procedures": PROCS},
               ensure_ascii=False, indent=2), encoding="utf-8")

ENT = {
    "proc_01_T1486": (
        [{"name": "CyberLock", "type": "malware"},
         {"name": "Mimikatz", "type": "hacker-tool"},
         {"name": "TotallyUnknownThing", "type": "security-product"}],
        [{"sub": "CyberLock", "rel": "uses", "rel_type": ["executes"], "obj": "Mimikatz"}],
    ),
    "proc_02_T1059.001": (
        [{"name": "PowerShell", "type": "general-software", "alias": ["powershell.exe"]},
         {"name": "Windows Registry Key", "type": "windows-registry-key"}],
        [{"sub": "PowerShell", "rel": "modifies",
          "rel_type": ["modifies-or-removes-or-replaces"], "obj": "Windows Registry Key"},
         {"sub": "PowerShell", "rel": "leads to", "rel_type": ["leads-to"],
          "obj": "Ghost Entity"}],
    ),
    "proc_03_T1027.009": ([], []),
}
for name, (ents, rels) in ENT.items():
    d = grid_raw / name
    d.mkdir()
    (d / "entities.json").write_text(json.dumps(ents, ensure_ascii=False, indent=2),
                                     encoding="utf-8")
    (d / "relation.json").write_text(json.dumps(rels, ensure_ascii=False, indent=2),
                                     encoding="utf-8")
    (d / "input.txt").write_text(
        next(p for p in PROCS if p["grid_dir"] == name)["procedure"], encoding="utf-8")

tm = B.build_type_mapping()
runs, pm = B.load_grid_runs(grid_raw, include_aggregate=False)
kg = B.build_kg(runs, pm, idx, tm,
                json.loads(Path("phuong_phap_2/kg.json").read_text(encoding="utf-8")))

st = kg["meta"]["stats"]
print("\n=== THONG KE (fixture tong hop - KHONG phai ket qua that) ===")
for k in ("runs", "grid_entities_seen", "grid_relations_seen", "reused_attack_nodes",
          "new_nodes", "uses_edges_inferred", "uses_edges_subject", "uses_edges_mentioned",
          "evidence_found", "evidence_partial", "evidence_missing", "skipped_self_loops",
          "technique_codes_in_text"):
    print(f"  {k:24s} {st.get(k, 0)}")
print("  entities_by_match         ", st["entities_by_match"])
print("  counts                    ", kg["meta"]["counts"])

print("\n=== KIEM TRA BAT BIEN ===")
ids = {n["id"] for n in kg["nodes"]}
print("  id node trung nhau                 :", len(ids) != len(kg["nodes"]))
print("  canh tro toi node khong ton tai    :",
      len([t for t in kg["triples"] if t["h"] not in ids or t["t"] not in ids]))
print("  nhan canh khong hop le cho Cypher  :",
      [t["r"] for t in kg["triples"] if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", t["r"])])
code_edges = [t for t in kg["triples"] if t.get("inferred_by") == "code"]
print("  so canh inferred_by=code            :", len(code_edges))
print("  canh code deu la USES               :", all(t["r"] == "USES" for t in code_edges))
print("  self-loop trong canh code           :",
      [t for t in code_edges if t["h"] == t["t"]])
print("  canh GRID thieu bang chung deu co flag:",
      all(t.get("evidence_status") for t in kg["triples"] if t.get("inferred_by") == "grid"))
print("  node technique tu regex ton tai     :", "T1112" in ids)
print("  node khop ATT&CK co external_id     :",
      sorted(n["id"] for n in kg["nodes"]
             if n.get("external_id") and n["id"] == n["external_id"]))
print("  node moi de trong external_id       :",
      all(not n.get("external_id") for n in kg["nodes"]
          if str(n["id"]).startswith("grid:")))
print("  node grid khong layer='grid'        :",
      sorted(n["id"] for n in kg["nodes"]
             if n.get("source") == "grid" and n.get("layer") not in ("grid", "report")))

# --- B5: mọi giá trị trong kg_full.json phải nạp được vào Neo4j -----------------
print("\n=== KIEM TRA TUONG THICH NEO4J (B5) ===")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "phuong_phap_2"))
try:
    import attack_kg_neo4j as NZ
except Exception as e:                      # neo4j driver chua cai -> bo qua, khong co la loi
    print("  bo qua (khong import duoc attack_kg_neo4j):", e)
else:
    base_ids = {n["id"] for n in
                json.loads(Path("phuong_phap_2/kg_base_scoped.json").read_text(encoding="utf-8"))["nodes"]}
    bad_val, bad_lab, bad_node_lab, layers = [], set(), set(), {}
    for n in kg["nodes"]:
        layers[n["id"]] = NZ.node_layer(n, n["id"] in base_ids)[0]
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", NZ.label(n["type"])):
            bad_node_lab.add(n["type"])
        for k, v in NZ.safe_props(n, drop=("source", "layer")).items():
            if isinstance(v, (dict, set)) or (
                    isinstance(v, list)
                    and not all(isinstance(x, (bool, int, float, str)) for x in v)):
                bad_val.append(("node", n["id"], k))
    for t in kg["triples"]:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", NZ.rel(t["r"])):
            bad_lab.add(t["r"])
        for k, v in NZ.safe_props(t, drop=("h", "r", "t", "source", "layer")).items():
            if isinstance(v, (dict, set)) or (
                    isinstance(v, list)
                    and not all(isinstance(x, (bool, int, float, str)) for x in v)):
                bad_val.append(("triple", t["h"], k))
    print("  nhan node khong hop le cho Cypher   :", sorted(bad_node_lab) or "khong co")
    print("  nhan canh khong hop le cho Cypher   :", sorted(bad_lab) or "khong co")
    print("  gia tri Neo4j khong nhan (dict/list):", bad_val or "khong co")
    print("  layer sau khi nap                    :", collections.Counter(layers.values()))
    print("  node nen giu layer='base'            :",
          all(layers[i] == "base" for i in base_ids if i in layers))
    print("  so canh GRID nap vao Neo4j           :",
          len([t for t in kg["triples"] if t.get("source") == "grid"]))

print(f"\nFile tam (KHONG dua vao out/): {tmp}")
