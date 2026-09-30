# -*- coding: utf-8 -*-
"""Thu hẹp MITRE ATT&CK về phạm vi "malware loader" (chỉ giữ Tactic + Technique),
và chuẩn hoá report_1.json (đổi ID technique đã bị MITRE thu hồi sang ID hiện hành).

Vì sao cần script này
--------------------
Bản enterprise-attack.json có 25.639 object đang hoạt động (697 technique, 730 malware,
176 intrusion-set, 56 campaign, 95 tool, analytic/detection-strategy/mitigation...).
Nạp tất cả vào Neo4j tạo ra một đồ thị quá rộng so với phạm vi nghiên cứu hiện tại.
Script này áp dụng 4 quy tắc lọc, mỗi quy tắc đều ghi lại lý do để truy vết được
(xem node["keep_reason"]).

4 quy tắc giữ technique
-----------------------
  R1  attack-evidence  : ATT&CK ghi nhận phần mềm loại *Loader/*Downloader/*Dropper/
                         *Stager thực sự `uses` technique này, VÀ technique nằm trong
                         8 tactic thuộc vòng đời loader.  -> bằng chứng từ chính dữ liệu
                         ATT&CK, không phải ý kiến cá nhân.
  R2  core-loader      : nằm trong danh sách lõi do người nghiên cứu định nghĩa
                         (CORE_TECHNIQUES bên dưới) - bổ sung cho R1 các technique
                         "chuẩn" của loader mà ATT&CK chưa gắn phần mềm nào.
  R3  report           : technique xuất hiện trong báo cáo CTI. Luôn giữ, kể cả khi
                         nằm ngoài phạm vi loader (đánh dấu in_loader_scope = false).
  R4  parent-closure   : technique cha của một sub-technique đã được giữ. Bắt buộc, vì
                         nếu giữ T1218.011 mà bỏ T1218 thì sub-technique sẽ mồ côi.

Quy tắc loại
------------
  L0  chỉ giữ 2 loại node: x-mitre-tactic và attack-pattern. Mọi loại khác
      (malware, tool, intrusion-set, campaign, course-of-action, data-component,
      x-mitre-analytic, x-mitre-detection-strategy, identity...) bị loại.
  L1  tactic ngoài vòng đời loader bị loại, TRỪ tactic có xuất hiện trong báo cáo.
  L2  technique không được R1..R4 giữ thì loại.
  L3  mọi cạnh có đầu mút bị loại cũng bị loại. Trong lớp nền chỉ giữ 2 loại quan hệ
      có nghĩa với phạm vi này: PART_OF (technique -> tactic) và SUBTECHNIQUE_OF.

Chuẩn hoá report
----------------
report_1.json do mô hình sinh ra nên có thể chứa ID đã bị MITRE thu hồi (ví dụ T1086 -
"PowerShell" - đã bị thay bằng T1059.001). Script tra quan hệ `revoked-by` trong STIX
để đổi sang ID hiện hành, tránh việc một technique thật bị rơi thành node mới.

Đầu vào
-------
  --attack  enterprise-attack.json
  --report  report_1.json
  --out     thư mục ghi kết quả

Đầu ra
------
  kg_base_scoped.json       lớp nền ATT&CK đã thu hẹp (đưa vào Neo4j bằng
                            attack_kg_neo4j.py --scoped)
  report_1.canonical.json   report đã chuẩn hoá ID (đưa vào dict_kg.py --report)
  scope_report.json         báo cáo kiểm toán: quy tắc, số lượng, node giữ/lỗi
"""
from __future__ import annotations

import argparse
import collections
import copy
import datetime as _dt
import json
import os
import re
import sys

try:    # console Windows mac dinh la cp1252, khong in duoc tieng Viet
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ---------------------------------------------------------------------------
# CẤU HÌNH PHẠM VI
# ---------------------------------------------------------------------------

SCOPE_NAME = "malware-loader"

# 8 tactic thuộc vòng đời malware loader: đến -> chạy -> tồn tại -> ẩn -> dò -> C2,
# cộng thêm phần chuẩn bị hạ tầng trước khi đến (Resource Development).
LOADER_TACTICS = (
    "initial-access",
    "execution",
    "persistence",
    "stealth",
    "defense-impairment",
    "discovery",
    "command-and-control",
    "resource-development",
)

# Tên ATT&CK đã đổi theo các bản mới: TA0005 từ "Defense Evasion" -> "Stealth",
# TA0112 -> "Defense Impairment". Không dùng tên làm khoá, dùng shortname.
KEEP_TYPES = {"x-mitre-tactic", "attack-pattern"}

# R2: danh sách lõi của malware loader, chỉ dùng ID đang hiệu lực.
# ID không tồn tại trong bundle sẽ bị báo lỗi ở bước kiểm tra, không bị bỏ qua âm thầm.
CORE_TECHNIQUES = """
    T1566 T1566.001 T1566.002 T1566.004
    T1204 T1204.001 T1204.002
    T1189 T1190 T1195 T1195.002
    T1583 T1583.001 T1583.003 T1583.004 T1583.006
    T1584 T1584.001
    T1587 T1587.001 T1588 T1588.001 T1588.002
    T1608 T1608.001 T1608.002 T1608.003
    T1059 T1059.001 T1059.003 T1059.005 T1059.006 T1059.007 T1059.009
    T1105 T1129 T1106 T1620 T1203
    T1218 T1218.001 T1218.002 T1218.005 T1218.008 T1218.010 T1218.011
    T1559 T1559.001 T1559.002
    T1564 T1564.001
    T1610 T1609
    T1547 T1547.001 T1547.009
    T1543 T1543.003
    T1546 T1546.003
    T1136 T1136.001
    T1574 T1574.001 T1574.008
    T1036 T1036.001 T1036.002 T1036.003 T1036.004 T1036.005 T1036.006 T1036.007
    T1027 T1027.004 T1027.008 T1027.009
    T1140 T1553 T1553.002 T1480
    T1497 T1497.001 T1497.003
    T1685 T1685.001 T1686 T1686.003
    T1070 T1070.006 T1222
    T1055 T1055.001 T1055.002 T1055.003 T1055.004
    T1134 T1134.001
    T1082 T1016 T1057 T1518 T1518.001 T1083 T1012 T1049 T1018
    T1071 T1071.001 T1071.004 T1095 T1573 T1573.002
    T1102 T1219 T1568 T1568.002 T1090 T1090.002 T1090.003 T1132
""".split()

# R1: phần mềm được coi là loader/dropper/stager theo chính tên + alias trong ATT&CK.
LOADER_SOFTWARE_RE = r"loader|downloader|dropper|stager"

REASONS = {
    "attack-evidence": "R1: ATT&CK ghi nhan phan mem loader/dropper/stager su dung",
    "core-loader": "R2: nam trong danh sach loi cua malware loader",
    "report": "R3: co trong bao cao CTI",
    "parent-closure": "R4: la technique cha cua mot sub-technique da giu",
    "tactic-scope": "L0: thuoc 8 tactic cua vong doi loader",
    "tactic-report": "L1: tactic xuat hien trong bao cao",
}


# ---------------------------------------------------------------------------
# TIEN ICH
# ---------------------------------------------------------------------------

def ext_id(obj):
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def tactics_of(obj):
    return {kc.get("phase_name") for kc in (obj.get("kill_chain_phases") or [])}


def walk_report(node, chunk_idx=None):
    """Đi đệ quy, lấy mọi dict có 'id' và 'procedure' (giữ chỉ số chunk)."""
    if isinstance(node, dict):
        if "id" in node and "procedure" in node:
            yield chunk_idx, node
        for value in node.values():
            yield from walk_report(value, chunk_idx)
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from walk_report(value, i if chunk_idx is None else chunk_idx)


# ---------------------------------------------------------------------------
# BƯỚC 0: nạp ATT&CK
# ---------------------------------------------------------------------------

def load_attack(path):
    """Trả về (active, by_stix, by_ext, revoked_by, revoked_by_stix).

    active     : object đang hiệu lực (không revoked, không deprecated)
    by_ext     : external_id -> object   (chỉ object active)
    revoked_by : external_id cũ -> [external_id mới]
    """
    bundle = json.load(open(path, encoding="utf-8"))
    all_objs = bundle["objects"]

    revoked_by = collections.defaultdict(set)
    by_stix_all = {o["id"]: o for o in all_objs}
    for o in all_objs:
        if o.get("type") != "relationship" or o.get("relationship_type") != "revoked-by":
            continue
        src = by_stix_all.get(o.get("source_ref"))
        dst = by_stix_all.get(o.get("target_ref"))
        if src and dst and ext_id(src) and ext_id(dst):
            revoked_by[ext_id(src)].add(ext_id(dst))

    active = [o for o in all_objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    by_stix = {o["id"]: o for o in active}
    by_ext = {}
    for o in active:
        eid = ext_id(o)
        if eid:
            by_ext[eid] = o
    return active, by_stix, by_ext, dict(revoked_by), by_stix_all


def is_loader_software(obj):
    haystack = " ".join([obj.get("name") or ""] + (obj.get("x_mitre_aliases") or []))
    return obj.get("type") in ("malware", "tool") and re.search(LOADER_SOFTWARE_RE, haystack, re.I) is not None


# ---------------------------------------------------------------------------
# BƯỚC 1: áp dụng 4 quy tắc giữ + quy tắc loại
# ---------------------------------------------------------------------------

def build_scope(active, by_stix, by_ext, revoked_by, report):
    reasons = collections.defaultdict(set)     # external_id -> {reason}
    audit = {"dropped_by_type": {}, "notes": []}

    # --- dữ liệu báo cáo: chuẩn hoá ID đã bị thu hồi, gom technique đã thấy ---
    report_tech, remaps, unknown_ids = {}, [], []
    for chunk_idx, item in walk_report(report):
        tid = (item.get("id") or "").strip()
        if not tid:
            continue
        procedure = (item.get("procedure") or "").strip()
        entry = report_tech.setdefault(tid, {"id": tid, "name": item.get("name"),
                                             "chunks": [], "procedures": []})
        entry["chunks"].append(chunk_idx)
        if procedure:
            entry["procedures"].append({"chunk": chunk_idx, "text": procedure})

    for tid in list(report_tech):
        if tid in by_ext:
            continue
        replacements = sorted(revoked_by.get(tid, []))
        hit = next((r for r in replacements if r in by_ext), None)
        if hit:
            remaps.append({"old_id": tid, "new_id": hit,
                           "old_name": report_tech[tid]["name"],
                           "new_name": by_ext[hit]["name"]})
            report_tech[hit] = report_tech.pop(tid)
            report_tech[hit]["remapped_from"] = tid
        else:
            unknown_ids.append(tid)

    for tid in report_tech:
        reasons[tid].add("report")

    # --- R1: bằng chứng từ chính dữ liệu ATT&CK ---
    loader_sw = [o for o in active if is_loader_software(o)]
    uses = collections.defaultdict(set)
    for o in active:
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses":
            uses[o.get("source_ref")].add(o.get("target_ref"))

    loader_tactic_set = set(LOADER_TACTICS)
    r1 = set()
    for sw in loader_sw:
        for target_stix in uses[sw["id"]]:
            target = by_stix.get(target_stix)
            if not target or target.get("type") != "attack-pattern":
                continue
            tid = ext_id(target)
            if tid and (tactics_of(target) & loader_tactic_set):
                r1.add(tid)
    for tid in r1:
        reasons[tid].add("attack-evidence")

    # --- R2: danh sách lõi ---
    r2 = {tid for tid in CORE_TECHNIQUES if tid in by_ext}
    unknown_core = sorted(set(CORE_TECHNIQUES) - set(by_ext))
    for tid in r2:
        reasons[tid].add("core-loader")

    # --- R3 đã xong ở trên ---

    # --- R4: đóng bằng technique cha (đi ngược qua quan hệ subtechnique-of) ---
    parent_of = {}
    for o in active:
        if o.get("type") == "relationship" and o.get("relationship_type") == "subtechnique-of":
            child, parent = by_stix.get(o.get("source_ref")), by_stix.get(o.get("target_ref"))
            if child and parent:
                cid, pid = ext_id(child), ext_id(parent)
                if cid and pid:
                    parent_of[cid] = pid

    r4 = set()
    frontier = set(reasons)
    while frontier:
        nxt = set()
        for tid in frontier:
            pid = parent_of.get(tid)
            if pid and pid not in reasons:
                reasons[pid].add("parent-closure")
                r4.add(pid)
                nxt.add(pid)
        frontier = nxt

    kept_tech = {tid: by_ext[tid] for tid in reasons if tid in by_ext}

    # L1: giữ tactic theo phạm vi loader, cộng thêm tactic có xuất hiện trong báo cáo.
    tactic_by_short = {}
    for o in active:
        if o.get("type") == "x-mitre-tactic" and o.get("x_mitre_shortname"):
            tactic_by_short[o["x_mitre_shortname"]] = o

    # chỉ xét các technique CỦA BÁO CÁO, không xét toàn bộ technique đã giữ
    report_tactic_ids = set()
    for tid in report_tech:
        obj = by_ext.get(tid)
        if not obj:
            continue
        for short in tactics_of(obj):
            tac = tactic_by_short.get(short)
            if tac:
                report_tactic_ids.add(ext_id(tac))

    kept_tactic = {}
    for short in LOADER_TACTICS:
        tac = tactic_by_short.get(short)
        if tac:
            kept_tactic[ext_id(tac)] = tac
            reasons[ext_id(tac)].add("tactic-scope")
    for tid in report_tactic_ids:
        if tid in by_ext:
            kept_tactic.setdefault(tid, by_ext[tid])
            reasons[tid].add("tactic-report")

    # --- L2: loại technique ngoài phạm vi ---
    dropped_tech = sorted(set(by_ext) & {t for t in by_ext if by_ext[t]["type"] == "attack-pattern"} - set(kept_tech))
    loader_scope_ids = {tid for tid in kept_tech
                        if reasons[tid] & {"attack-evidence", "core-loader", "parent-closure"}}

    # --- thống kê loại theo loại node (L0) ---
    by_type = collections.Counter(o.get("type") for o in active)
    kept_types = collections.Counter(o.get("type") for o in kept_tactic.values()) + \
        collections.Counter(o.get("type") for o in kept_tech.values())
    audit["dropped_by_type"] = {
        t: {"total": by_type[t], "kept": kept_types.get(t, 0), "dropped": by_type[t] - kept_types.get(t, 0)}
        for t in sorted(by_type)
    }

    return {
        "reasons": {k: sorted(v) for k, v in reasons.items()},
        "kept_tactic": kept_tactic,
        "kept_tech": kept_tech,
        "loader_scope_ids": loader_scope_ids,
        "dropped_tech": dropped_tech,
        "report_tech": report_tech,
        "remaps": remaps,
        "unknown_ids": unknown_ids,
        "unknown_core": unknown_core,
        "loader_software": [{"id": ext_id(o), "name": o.get("name"), "type": o.get("type")}
                            for o in loader_sw],
        "r1": sorted(r1),
        "r2": sorted(r2),
        "r3": sorted(report_tech),
        "r4": sorted(r4),
        "tactic_by_short": tactic_by_short,
        "parent_of": parent_of,
        "audit": audit,
    }


# ---------------------------------------------------------------------------
# BƯỚC 2: xuất lớp nền đã thu hẹp
# ---------------------------------------------------------------------------

def export_base(scope, attack_path, out_path):
    """Xuất lớp nền = ĐỊNH NGHĨA phạm vi malware loader.

    Chỉ node thật sự thuộc phạm vi loader mới vào lớp nền (in_loader_scope = True).
    Technique chỉ tồn tại vì báo cáo nhắc tới (in_loader_scope = False) KHÔNG vào đây;
    chúng sẽ do lớp báo cáo tạo ra trong attack_kg_neo4j.py với layer = "report".
    """
    nodes, triples = [], []

    loader_tactic_ids = {ext_id(t) for s in LOADER_TACTICS
                         if (t := scope["tactic_by_short"].get(s))}
    for tid in sorted(loader_tactic_ids):
        obj = scope["kept_tactic"][tid]
        nodes.append({
            "id": tid,
            "type": "x-mitre-tactic",
            "name": obj.get("name"),
            "external_id": tid,
            "stix_id": obj["id"],
            "source": "attack",
            "layer": "base",
            "in_loader_scope": True,
            "keep_reason": scope["reasons"].get(tid) or ["tactic-scope"],
        })

    for tid, obj in sorted(scope["kept_tech"].items()):
        if tid not in scope["loader_scope_ids"]:
            continue
        nodes.append({
            "id": tid,
            "type": "attack-pattern",
            "name": obj.get("name"),
            "external_id": tid,
            "stix_id": obj["id"],
            "url": next((r.get("url") for r in obj.get("external_references", []) or []
                         if r.get("source_name") == "mitre-attack"), None),
            "description": (obj.get("description") or "")[:400],
            "is_subtechnique": "." in tid,
            "source": "attack",
            "layer": "base",
            "in_loader_scope": True,
            "keep_reason": scope["reasons"].get(tid, []),
        })

    base_ids = {n["id"] for n in nodes}

    # PART_OF: suy ra tu kill_chain_phases cua technique -> tactic da giu
    for tid, obj in sorted(scope["kept_tech"].items()):
        if tid not in base_ids:
            continue
        for short in sorted(tactics_of(obj)):
            tac = scope["tactic_by_short"].get(short)
            if not tac:
                continue
            tac_id = ext_id(tac)
            if tac_id in base_ids:
                triples.append({"h": tid, "r": "part_of", "t": tac_id,
                                "source": "attack", "layer": "base"})

    # SUBTECHNIQUE_OF: sub-technique -> technique cha (cha cung duoc giu o R4)
    for tid in sorted(base_ids):
        parent = scope["parent_of"].get(tid)
        if parent and parent in base_ids:
            triples.append({"h": tid, "r": "subtechnique_of", "t": parent,
                            "source": "attack", "layer": "base"})

    report_only = sorted(set(scope["kept_tech"]) - scope["loader_scope_ids"])
    meta = {
        "scope": SCOPE_NAME,
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "attack_bundle": os.path.basename(attack_path),
        "loader_tactics": list(LOADER_TACTICS),
        "rules": REASONS,
        "stats": {
            "kept_nodes": len(nodes),
            "kept_edges": len(triples),
            "kept_tactics": len(loader_tactic_ids),
            "kept_techniques": len(base_ids) - len(loader_tactic_ids),
            "in_loader_scope": len(base_ids) - len(loader_tactic_ids),
            "report_only_not_in_base": len(report_only),
        },
        "report_only_techniques": report_only,
    }
    json.dump({"meta": meta, "nodes": nodes, "triples": triples},
              open(out_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return meta


# ---------------------------------------------------------------------------
# BƯỚC 3: xuất report đã chuẩn hoá + báo cáo kiểm toán
# ---------------------------------------------------------------------------

def export_report_canonical(report, scope, out_path):
    """Viết lại report_1.json với ID đã chuẩn hoá (giữ nguyên cấu trúc list-of-chunk)."""
    remap = {r["old_id"]: r["new_id"] for r in scope["remaps"]}
    tac_name = {ext_id(t): t.get("name") for t in scope["tactic_by_short"].values()}

    def fix(node):
        if isinstance(node, dict):
            out = {}
            for key, value in node.items():
                if key == "id" and isinstance(value, str):
                    old = value
                    new = remap.get(old, old)
                    out["id"] = new
                    if new != old:
                        out["original_id"] = old
                        out["canonicalized"] = True
                else:
                    out[key] = fix(value)
            if "id" in out and out["id"] in tac_name and "report_name" not in out:
                out["report_name"] = out.get("name")
                out["name"] = tac_name[out["id"]]
            return out
        if isinstance(node, list):
            return [fix(v) for v in node]
        return node

    data = fix(copy.deepcopy(report))
    json.dump(data, open(out_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


def export_audit(scope, meta, out_path):
    def by_reason(tid):
        return scope["reasons"].get(tid, [])

    loader_tactic_ids = {ext_id(t) for s in LOADER_TACTICS
                         if (t := scope["tactic_by_short"].get(s))}
    audit = {
        "scope": SCOPE_NAME,
        "generated_at": meta["generated_at"],
        "loader_tactics": list(LOADER_TACTICS),
        "rules": REASONS,
        "rule_counts": {"R1_attack_evidence": len(scope["r1"]),
                        "R2_core_loader": len(scope["r2"]),
                        "R3_report": len(scope["r3"]),
                        "R4_parent_closure": len(scope["r4"])},
        "stats": meta["stats"],
        "base_layer": {
            "tactics": [{"id": t, "name": scope["kept_tactic"][t].get("name"),
                         "keep_reason": by_reason(t)} for t in sorted(loader_tactic_ids)],
            "techniques": [{"id": t, "name": o.get("name"),
                            "keep_reason": by_reason(t),
                            "tactics": sorted(tactics_of(o))}
                           for t, o in sorted(scope["kept_tech"].items())
                           if t in scope["loader_scope_ids"]],
        },
        "report_only": {
            "explanation": "technique chi co trong bao cao, nam ngoai dinh nghia pham vi loader; "
                           "duoc tao o layer='report' chu khong dua vao lop nen",
            "techniques": [{"id": t, "name": scope["kept_tech"][t].get("name"),
                            "tactics": sorted(tactics_of(scope["kept_tech"][t]))}
                           for t in meta["report_only_techniques"]],
        },
        "dropped": {
            "by_node_type": scope["audit"]["dropped_by_type"],
            "tactics": [{"id": ext_id(o), "name": o.get("name"),
                         "shortname": o.get("x_mitre_shortname")}
                        for o in scope["tactic_by_short"].values()
                        if ext_id(o) not in loader_tactic_ids],
            "techniques_out_of_scope_count": len(scope["dropped_tech"]),
            "techniques_out_of_scope_sample": scope["dropped_tech"][:40],
        },
        "loader_software_used_for_evidence": scope["loader_software"],
        "report": {
            "techniques": scope["r3"],
            "id_remapped": scope["remaps"],
            "id_unknown": scope["unknown_ids"],
            "core_list_ids_not_in_attack": scope["unknown_core"],
            "procedures_present": sum(1 for v in scope["report_tech"].values() if v["procedures"]),
            "out_of_loader_scope_techniques": sorted(
                t for t in scope["r3"] if t not in scope["loader_scope_ids"]
            ),
        },
    }
    json.dump(audit, open(out_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return audit


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Thu hep MITRE ATT&CK ve pham vi malware loader")
    ap.add_argument("--attack", default="enterprise-attack.json")
    ap.add_argument("--report", default="report_1.json")
    ap.add_argument("--out", default=".")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    report = json.load(open(a.report, encoding="utf-8"))
    active, by_stix, by_ext, revoked_by, _ = load_attack(a.attack)

    n_attack = sum(1 for o in active if o.get("type") == "attack-pattern")
    n_tactic = sum(1 for o in active if o.get("type") == "x-mitre-tactic")
    print(f"ATT&CK dang hieu luc: {n_attack} technique, {n_tactic} tactic, "
          f"{len(active)} object")

    scope = build_scope(active, by_stix, by_ext, revoked_by, report)

    base_path = os.path.join(a.out, "kg_base_scoped.json")
    canon_path = os.path.join(a.out, "report_1.canonical.json")
    audit_path = os.path.join(a.out, "scope_report.json")

    meta = export_base(scope, a.attack, base_path)
    export_report_canonical(report, scope, canon_path)
    audit = export_audit(scope, meta, audit_path)

    print(f"pham mem loader/dropper/stager (R1): {len(scope['loader_software'])} software")
    print(f"R1 attack-evidence : {len(scope['r1'])} technique")
    print(f"R2 core-loader     : {len(scope['r2'])} technique")
    print(f"R3 report          : {len(scope['r3'])} technique")
    print(f"R4 parent-closure  : {len(scope['r4'])} technique")
    print(f"-> lop nen (dinh nghia malware loader): {meta['stats']['kept_nodes']} node "
          f"({meta['stats']['kept_techniques']} technique + {meta['stats']['kept_tactics']} tactic), "
          f"{meta['stats']['kept_edges']} canh")
    print(f"   chi co trong bao cao, nam ngoai pham vi loader: "
          f"{meta['stats']['report_only_not_in_base']} technique -> {meta['report_only_techniques']}")
    print(f"   loai {n_attack + n_tactic - meta['stats']['kept_nodes']} node ATT&CK ra khoi pham vi")
    if scope["remaps"]:
        print("chuan hoa ID bao cao:")
        for r in scope["remaps"]:
            print(f"   {r['old_id']} ({r['old_name']}) -> {r['new_id']} ({r['new_name']})")
    if scope["unknown_ids"]:
        print("CANH BAO - ID bao cao khong tim thay trong ATT&CK:", scope["unknown_ids"])
    if scope["unknown_core"]:
        print("CANH BAO - ID trong danh sach loi khong ton tai:", scope["unknown_core"])

    print(f"\nda ghi: {base_path}\n         {canon_path}\n         {audit_path}")


if __name__ == "__main__":
    main()
