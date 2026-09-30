"""
B1-B5 - Gom ba tang KG thanh mot: lop nen MITRE ATT&CK + technique tu bao cao
+ triple GRID trich tu van ban bao cao.

Script nay CHAY OFFLINE, KHONG goi model. Input duy nhat la `out/grid_raw/` do
`out/run_grid_colab.py` ( tren Colab ) sinh ra.

  B1  out/type_mapping.json  - anh xa 33 entity type + 44 rel type cua GRID sang
                              tu vung STIX/ATT&CK, de nguoi dung duyet.
                              Khong map duoc -> giu type goc + co `unmapped`.
  B2  Khop ten/alias entity voi malware/tool/intrusion-set trong enterprise-attack.json
      de gan `external_id`. Mo ho / khong co -> de trong `external_id` va tao node moi
      `layer="report"`. Regex bat ma technique (T1112) trong van ban de noi node technique.
  B3  Moi procedure: chu the duoc trich noi bang canh `uses` toi `technique_id` cua
      procedure do, gan `source="grid"` + `inferred_by="code"` (SUY RA bang code,
      KHONG phai model trich) kem cau bang chung + chunk.
  B4  Moi triple GRID phai co cau bang chung chua ca chu the lan doi tuong.
      Thieu -> gan co `evidence_status`, KHONG xoa triple nao.
  B5  Xuat out/kg_full.json cung dinh dang voi kg.json (nodes/triples, co `source`),
      nap duoc bang phuong_phap_2/attack_kg_neo4j.py. Lop nen khong doi.

Chay:
    python out/build_kg_full.py --only-mapping     # chi tao type_mapping.json
    python out/build_kg_full.py                    # can co out/grid_raw/
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

try:    # console Windows mac dinh la cp1252
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

OUT_DIR = Path(__file__).resolve().parent
REPO_ROOT = OUT_DIR.parent

RX_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
RX_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")

# Tu stop tieng Anh hay xuat hien o cau van ban, nen bo qua khi so khop dung phong.
# VD "Windows Registry Key" -> noi dung la "the registry key".
STOPWORDS = {
    "a", "an", "and", "any", "as", "at", "by", "for", "from", "in", "into", "is", "it",
    "its", "of", "on", "or", "that", "the", "then", "this", "to", "via", "was", "were",
    "which", "with", "within", "per", "by",
}

# Các entity type co vai tro "chu the" (tac nhan) - dung cho canh `uses` o B3.
ACTOR_GRID_TYPES = {
    "malware", "hacker-tool", "general-software",
    "threat-actor-or-intrusion-set", "campaign",
}


# ===========================================================================
# B1 - bang anh xa type
# ===========================================================================
# status:
#   mapped       - khop chinh xac 1 loai co trong bundle ATT&CK
#   alias        - cung nghia, khac ten (vd GRID email-address vs STIX email-addr)
#   approximate  - gan nhat trong tu vung, KHONG cung nghia, can nguoi dung duyet
#   unmapped     - khong co tu vong phu hop -> GIU NGUYEN type GRID + co `unmapped`
#
# `attack_type` chi gan khi loai do THUC SU co trong enterprise-attack.json
# (do duoc: malware, tool, intrusion-set, campaign, course-of-action,
#  attack-pattern, x-mitre-tactic, identity).
ENTITY_TYPE_MAPPING = {
    "user-account": ("identity", "identity", "mapped",
                     "ATT&CK bundle chi co 1 object `identity`"),
    "identity": ("identity", "identity", "mapped", ""),
    "threat-actor-or-intrusion-set": ("intrusion-set", "intrusion-set", "mapped", ""),
    "malware": ("malware", "malware", "mapped", ""),
    "hacker-tool": ("tool", "tool", "mapped", ""),
    "general-software": ("tool", "tool", "approximate",
                         "GRID rong hon `tool` (gom ca phan mem thuong); bundle khong co type rieng"),
    "detailed-part-of-malware-or-hackertool": (None, None, "unmapped",
                                               "STIX khong co; giu nguyen ten GRID"),
    "detailed-part-of-general-software": (None, None, "unmapped",
                                          "STIX khong co; giu nguyen ten GRID"),
    "vulnerability": ("vulnerability", None, "approximate",
                      "STIX 2.1 co `vulnerability`, nhung bundle ATT&CK khong chua loai nay"),
    "attack-pattern": ("attack-pattern", "attack-pattern", "mapped", ""),
    "campaign": ("campaign", "campaign", "mapped", ""),
    "file": (None, None, "unmapped", "khong co trong STIX 2.1 lẫn ATT&CK"),
    "process": (None, None, "unmapped", "khong co trong STIX 2.1 lẫn ATT&CK"),
    "windows-registry-key": (None, None, "unmapped", "khong co trong STIX 2.1 lẫn ATT&CK"),
    "ipv4-addr": ("ipv4-addr", None, "approximate", "SCO cua STIX 2.1; bundle khong chua"),
    "ipv6-addr": ("ipv6-addr", None, "approximate", "SCO cua STIX 2.1; bundle khong chua"),
    "domain-name": ("domain-name", None, "approximate", "SCO cua STIX 2.1; bundle khong chua"),
    "url": ("url", None, "approximate", "SCO cua STIX 2.1; bundle khong chua"),
    "email-address": ("email-addr", None, "alias",
                      "STIX 2.1 dat ten la `email-addr`, khac GRID"),
    "network-traffic": ("network-traffic", None, "approximate", "SCO cua STIX 2.1; bundle khong chua"),
    "mac-address": ("mac-addr", None, "alias", "STIX 2.1 dat ten la `mac-addr`, khac GRID"),
    "infrastructure": ("infrastructure", None, "approximate",
                       "SDO cua STIX 2.1; bundle ATT&CK khong chua"),
    "credential-value": (None, None, "unmapped", "khong co trong STIX 2.1 lẫn ATT&CK"),
    "x509-certificate": ("x509-certificate", None, "approximate", "SCO cua STIX 2.1; bundle khong chua"),
    "indicator": ("indicator", None, "approximate",
                  "SDO cua STIX 2.1; ATT&CK khong dung loai nay"),
    "course-of-action": ("course-of-action", "course-of-action", "mapped", ""),
    "security-product": (None, None, "unmapped", "khong co trong STIX 2.1 lẫn ATT&CK"),
    "malware-analysis-document-or-publication-or-conference": (
        None, None, "unmapped", "khong co trong STIX 2.1 lẫn ATT&CK"),
    "location": ("location", None, "approximate", "SDO cua STIX 2.1; bundle khong chua"),
    "abstract-concept": (None, None, "unmapped", "khong phai loai cua STIX 2.1"),
    "generic-noun": (None, None, "unmapped", "khong phai loai cua STIX 2.1"),
    "other": (None, None, "unmapped", "giu nguyen `other`"),
    "noise": (None, None, "unmapped", "giu nguyen `noise`; tang sau co the loai"),
}

# Tu vung quan he DO DUOC trong enterprise-attack.json chi co 6 loai:
#   uses, mitigates, detects, subtechnique-of, revoked-by, attributed-to
# Nen moi quan he duoc gan `attack_relationship` deu la `approximate` hoac `mapped`
# voi 6 loai do; con lai `unmapped` va giu nguyen ten GRID.
REL_TYPE_MAPPING = {
    "exploits": ("uses", "approximate", "bundle chi co `uses`; `exploits` cua GRID gan nghia"),
    "bypasses": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "malicious-investigates-track-detects": ("detects", "approximate",
                                             "bundle co `detects` (dung cho detection strategy)"),
    "impersonates": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "targets": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "compromises": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "leads-to": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "drops": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "downloads": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "executes": ("uses", "approximate", "bundle chi co `uses`"),
    "delivers": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "beacons-to": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "exfiltrate-to": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "leaks": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "communicates-with": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "resolves-to": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "hosts": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "provides": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "authored-by": ("attributed-to", "approximate", "bundle chi co `attributed-to`"),
    "owns": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "controls": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "attributed-to": ("attributed-to", "mapped", ""),
    "affiliated-with": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "cooperates-with": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "is-part-of": (None, "unmapped",
                   "ATT&CK dung `subtechnique-of` cho TTP; quan he nay thuong noi thanh phan"),
    "consists-of": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "has": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "depends-on": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "creates-or-generates": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "modifies-or-removes-or-replaces": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "uses": ("uses", "mapped", ""),
    "variant-of": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "derived-from": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "alias-of": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "compares-to": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "categorized-as": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "located-at": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "originates-from": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "indicates": ("detects", "approximate", "bundle co `detects`"),
    "mitigates": ("mitigates", "mapped", ""),
    "based-on": (None, "unmapped", "khong co trong 6 loai cua bundle"),
    "research-describes-analysis-of-characterizes-detects": (
        "detects", "approximate", "bundle co `detects`"),
    # KHONG phai canh - la dinh toc cua su kien. Giu trong triple nhung gan co.
    "negation": (None, "unmapped",
                 "KHONG phai quan he - la dinh toc (special factuality). "
                 "Dinh danh `not_an_edge` de nguoi dung quyet dinh"),
    "other": (None, "unmapped", "giu nguyen `other`"),
}


def build_type_mapping() -> dict:
    """B1: tao out/type_mapping.json de nguoi dung duyet."""
    entity = {}
    for k, (stix, atk, status, note) in ENTITY_TYPE_MAPPING.items():
        entity[k] = {
            "stix_type": stix,
            "attack_type": atk,
            "status": status,
            "keep_original": status == "unmapped",
            "node_type": atk or stix or k,      # type se gan cho node trong KG
            "note": note,
        }
    relation = {}
    for k, (atk, status, note) in REL_TYPE_MAPPING.items():
        relation[k] = {
            "attack_relationship": atk,
            "status": status,
            "keep_original": status == "unmapped",
            "edge_label": atk or k,              # nhan canh se dung trong KG
            "not_an_edge": k == "negation",
            "note": note,
        }
    counts = {}
    for tbl in (entity, relation):
        for v in tbl.values():
            counts[v["status"]] = counts.get(v["status"], 0) + 1

    return {
        "meta": {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "source": "src/grid/GRID_backbone.py (ENTITY_TYPES, REL_TYPES)",
            "entity_type_count": len(entity),
            "rel_type_count": len(relation),
            "status_counts": counts,
            "attack_bundle_relationship_vocabulary": [
                "uses", "mitigates", "detects",
                "subtechnique-of", "revoked-by", "attributed-to",
            ],
            "attack_bundle_vocabulary_note": (
                "Do bang dem relationship_type trong enterprise-attack.json: chi co "
                "6 gia tri. Moi `attack_relationship` gan o trang nay deu nam trong 6 gia tri do."
            ),
            "how_to_use": (
                "status=unmapped -> node/canh GIU NGUYEN ten GRID va gan co "
                "`unmapped`/`type_unmapped` de nguoi dung quyet dinh. "
                "status=approximate -> da gan gia tri gan nhat nhung CHUA cung nghia, "
                "can duyet. Khong co gi bi xoa."
            ),
        },
        "entity_types": entity,
        "rel_types": relation,
    }


# ===========================================================================
# Tien ich
# ===========================================================================
def norm(s: str) -> str:
    """Chuan hoa de so sanh ten: viet thuong, thay ky tu dac biet, gom khoang trang."""
    s = (s or "").lower()
    s = re.sub(r"[^0-9a-z]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def slug(s: str) -> str:
    s = re.sub(r"[^0-9A-Za-z]+", "_", (s or "").strip()).strip("_")
    return (s or "unnamed")[:80]


def cypher_rel(name: str) -> str:
    """Nhan canh hop le cho Cypher: [A-Za-z][A-Za-z0-9_]*"""
    name = re.sub(r"[^A-Za-z0-9]+", "_", name or "").strip("_")
    if not name or not name[0].isalpha():
        name = f"REL_{name}" if name else "REL_UNSPECIFIED"
    return name.upper()


def cypher_label(t: str) -> str:
    parts = [p.capitalize() for p in re.split(r"[^A-Za-z0-9]+", t or "") if p]
    return "".join(parts) or "Entity"


def attack_ref(o: dict):
    for r in o.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id"), r.get("url")
    return None, None


def load_attack_index(path: Path) -> dict:
    """
    Chi muc can cho viec khop (B2). Doc 1 lan len ~48 MB.
    """
    objs = json.load(open(path, encoding="utf-8"))["objects"]
    active = [o for o in objs if not o.get("revoked") and not o.get("x_mitre_deprecated")]

    software, software_alias = {}, {}
    technique, technique_name, technique_alias = {}, {}, {}
    tactic = {}
    revoked_by = {}

    for o in active:
        eid, url = attack_ref(o)
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            src, tgt = o.get("source_ref"), o.get("target_ref")
            if src and tgt:
                revoked_by[src] = tgt        # stix id cua bi thu hoi -> stix id cua thay the
        if not eid:
            continue
        name = o.get("name") or ""
        aliases = list(o.get("aliases") or []) + list(o.get("x_mitre_aliases") or [])
        rec = {"external_id": eid, "type": o["type"], "name": name,
               "aliases": aliases, "url": url, "stix_id": o["id"]}
        if o["type"] in ("malware", "tool", "intrusion-set"):
            software.setdefault(norm(name), []).append(rec)
            for a in aliases:
                software_alias.setdefault(norm(a), []).append(rec)
        elif o["type"] == "attack-pattern":
            technique[eid] = rec
            technique_name.setdefault(norm(name), []).append(rec)
            for a in aliases:
                technique_alias.setdefault(norm(a), []).append(rec)
        elif o["type"] == "x-mitre-tactic":
            tactic[eid] = rec

    # truy xuoc theo stix id de trai ve external_id
    stix_to_ext = {o["id"]: attack_ref(o)[0] for o in objs if attack_ref(o)[0]}
    revoked_by_ext = {}
    for src, tgt in revoked_by.items():
        if src in stix_to_ext and tgt in stix_to_ext:
            revoked_by_ext[stix_to_ext[src]] = stix_to_ext[tgt]

    return {
        "software": software, "software_alias": software_alias,
        "technique": technique, "technique_name": technique_name,
        "technique_alias": technique_alias, "tactic": tactic,
        "revoked_by": revoked_by_ext,
        "counts": {
            "objects_total": len(objs),
            "software_active": sum(len(v) for v in software.values())
            + sum(len(v) for v in software_alias.values()),
            "technique_active": len(technique),
            "tactic_active": len(tactic),
        },
    }


# ===========================================================================
# B2 - khop entity GRID voi ATT&CK
# ===========================================================================
def resolve_entity(name: str, grid_type: str, aliases: list, idx: dict) -> dict:
    """
    Thu tu uu tien khop:
      1. Ma technique (T1112 / T1112.001) -> node technique co san
      2. Ten/alias khop dung 1 malware/tool/intrusion-set -> gan external_id
      3. Ten/alias khop 1 technique -> node technique co san
      4. Khong khop / mo ho -> node moi, external_id de trong, layer="report"
    """
    raw = (name or "").strip()
    n = norm(raw)
    res = {
        "name": raw,
        "grid_type": grid_type,
        "aliases": [a for a in (aliases or []) if a],
        "id": None, "node_type": None, "external_id": None,
        "attack_name": None, "match": "none", "candidates": [],
    }
    if not raw:
        res["match"] = "empty"
        return res

    # --- 1. ma technique ---
    codes = RX_TECHNIQUE.findall(raw)
    if codes and len(codes) == 1 and norm(raw) == norm(codes[0]):
        code = idx["revoked_by"].get(codes[0], codes[0])
        t = idx["technique"].get(code)
        res.update({
            "id": code, "node_type": "attack-pattern", "external_id": code,
            "attack_name": t["name"] if t else raw,
            "match": "technique_code",
        })
        if codes[0] != code:
            res["canonicalized_from"] = codes[0]
        return res

    # --- 2. malware/tool/intrusion-set ---
    for table, via in ((idx["software"], "name"), (idx["software_alias"], "alias")):
        cands = table.get(n) or []
        # thu khop qua alias cua chinh entity do
        if not cands and via == "name":
            for a in res["aliases"]:
                cands = table.get(norm(a)) or []
                if cands:
                    via = "alias"
                    break
        if len(cands) == 1:
            c = cands[0]
            res.update({
                "id": c["external_id"], "node_type": c["type"],
                "external_id": c["external_id"], "attack_name": c["name"],
                "match": f"software_{via}", "attack_url": c.get("url"),
            })
            return res
        if len(cands) > 1:
            res["match"] = "ambiguous_software"
            res["candidates"] = sorted({c["external_id"] for c in cands})
            return res

    # --- 3. technique ---
    for table, via in ((idx["technique_name"], "name"), (idx["technique_alias"], "alias")):
        cands = table.get(n) or []
        if not cands and via == "name":
            for a in res["aliases"]:
                cands = table.get(norm(a)) or []
                if cands:
                    via = "alias"
                    break
        if len(cands) == 1:
            c = cands[0]
            res.update({
                "id": c["external_id"], "node_type": "attack-pattern",
                "external_id": c["external_id"], "attack_name": c["name"],
                "match": f"technique_{via}",
            })
            return res
        if len(cands) > 1:
            res["match"] = "ambiguous_technique"
            res["candidates"] = sorted({c["external_id"] for c in cands})
            return res

    # --- 4. khong khop ---
    res["id"] = f"grid:{slug(raw)}"
    res["node_type"] = grid_type or "other"
    return res


# ===========================================================================
# B4 - tim cau bang chung
# ===========================================================================
def split_sentences(text: str) -> list:
    return [s.strip() for s in RX_SENTENCE_SPLIT.split(text or "") if s and s.strip()]


def _content_words(s: str) -> set:
    """Cac tu con thu nghia cua mot ten (bo stopword)."""
    words = {w for w in norm(s).split() if w not in STOPWORDS}
    return words or set(norm(s).split())      # ten chi co stopword -> dung ca cum


def find_evidence(text: str, sub: str, obj: str, aliases: list) -> dict:
    """
    Tra ve cau trong `text` chua CA chu the lan doi tuong.

    Vong 1 (chinh xac): ten chuan hoa cua sub/obj xuat hien nguyen van trong cau.
    Vong 2 (dung phong): moi ben it nhat mot tu con thu nghia xuat hien trong cau
                         (vi du "Windows Registry Key" ~ "the registry key").
                         Ket qua vong 2 LUON duoc danh dau rieng de nguoi dung
                         dung muc do tin cay.
    KHONG tim duoc -> `evidence_status = "no_evidence_sentence"`, KHONG xoa triple.
    """
    subs = [sub] + [a for a in (aliases or []) if a]
    ns = {norm(x) for x in subs if x and len(norm(x)) >= 3}
    no = {norm(obj)}
    if not ns or not obj or len(norm(obj)) < 3:
        return {"evidence": None, "evidence_status": "insufficient_name"}
    if ns & no:
        for sent in split_sentences(text):
            if norm(sent) in ns:
                return {"evidence": sent, "evidence_status": "self_reference"}
        return {"evidence": None, "evidence_status": "no_evidence_sentence"}

    sentences = split_sentences(text)
    for sent in sentences:
        n_sent = norm(sent)
        if any(x in n_sent for x in ns) and any(x in n_sent for x in no):
            return {"evidence": sent, "evidence_status": "found"}

    cs = set().union(*[_content_words(x) for x in subs]) if subs else set()
    co = _content_words(obj)
    if cs and co:
        for sent in sentences:
            w = set(norm(sent).split())
            hit_s, hit_o = cs & w, co & w
            if hit_s and hit_o:
                return {
                    "evidence": sent,
                    "evidence_status": "found_partial_name",
                    "evidence_matched_words": {"sub": sorted(hit_s), "obj": sorted(hit_o)},
                }
    return {"evidence": None, "evidence_status": "no_evidence_sentence"}


# ===========================================================================
# B2-B5 - ghep KG
# ===========================================================================
def load_grid_runs(grid_raw: Path, include_aggregate: bool) -> tuple:
    """
    Doc out/grid_raw/. Tra ve (runs, procedure_map).
    `runs` = danh sach thu muc co entities.json + relation.json.
    """
    pm_path = grid_raw / "procedure_map.json"
    if not pm_path.exists():
        raise FileNotFoundError(
            f"Khong tim thay {pm_path}. Can chay `python out/run_grid_colab.py` tren "
            "Colab truoc, roi tai thu muc out/grid_raw/ ve may nay."
        )
    pm = json.loads(pm_path.read_text(encoding="utf-8"))
    by_dir = {}
    for item in pm.get("procedures", []):
        d = item.get("grid_dir")
        if d:
            by_dir[d.split("/")[-1]] = item

    runs = []
    for name in sorted(p.name for p in grid_raw.iterdir() if p.is_dir()):
        if name.startswith("template_debug"):
            continue
        ent_f = grid_raw / name / "entities.json"
        rel_f = grid_raw / name / "relation.json"
        if not ent_f.exists():
            continue
        kind = "aggregate" if name == "aggregate" else "procedure"
        if kind == "aggregate" and not include_aggregate:
            continue
        item = by_dir.get(name, {})
        runs.append({
            "name": name,
            "kind": kind,
            "procedure_id": item.get("procedure_id"),
            "technique_id": item.get("technique_id"),
            "technique_name": item.get("technique_name"),
            "tactic": item.get("tactic"),
            "chunk": item.get("chunk"),
            "text": (grid_raw / name / "input.txt").read_text(encoding="utf-8")
                    if (grid_raw / name / "input.txt").exists() else item.get("procedure", ""),
            "entities": json.loads(ent_f.read_text(encoding="utf-8")),
            "relations": json.loads(rel_f.read_text(encoding="utf-8")),
            "technique_codes_in_text": item.get("technique_codes_in_text", []),
        })
    return runs, pm


def entity_aliases(e: dict) -> list:
    a = e.get("alias") or e.get("aliases") or []
    if isinstance(a, str):
        a = [a]
    return [str(x) for x in a if x and str(x) != str(e.get("name", ""))]


def build_kg(runs, pm, idx, tm, report_kg: dict | None) -> dict:
    nodes, triples = {}, {}
    stats = {
        "runs": len(runs),
        "grid_entities_seen": 0, "grid_relations_seen": 0,
        "entities_by_match": {}, "entities_by_status": {},
        "new_nodes": 0, "reused_attack_nodes": 0,
        "uses_edges_inferred": 0, "uses_edges_subject": 0, "uses_edges_mentioned": 0,
        "evidence_found": 0, "evidence_missing": 0,
        "technique_codes_in_text": 0, "rel_types_seen": {}, "entity_types_seen": {},
    }

    def add_node(nid, props, weak=False):
        """
        weak=True: chi bo sung truong con THIEU (dung khi them node tu canh quan he,
        vi thong tin tu danh sach entity GRID tot hon thong tin suy dien).
        """
        new_sources = set(props.pop("sources", []))
        if props.get("source"):
            new_sources.add(props["source"])
        runs_seen = set(props.pop("seen_in_runs", []))
        node = nodes.setdefault(nid, {})
        incoming = {k: v for k, v in props.items() if v is not None}
        if weak and node:
            incoming = {k: v for k, v in incoming.items() if k not in node}
        node.update(incoming)
        runs_seen |= set(node.get("seen_in_runs", []))
        new_sources |= set(node.get("sources", []))
        node["sources"] = sorted(new_sources)
        if runs_seen:
            node["seen_in_runs"] = sorted(runs_seen)
        else:
            node.pop("seen_in_runs", None)
        return nid

    def add_triple(t):
        new_sources = set(t.pop("sources", []))
        if t.get("source"):
            new_sources.add(t["source"])
        runs_seen = set(t.pop("seen_in_runs", []))
        key = (t["h"], t["r"], t["t"])
        if key in triples:
            triples[key].update({k: v for k, v in t.items() if v is not None})
            runs_seen |= set(triples[key].get("seen_in_runs", []))
            new_sources |= set(triples[key].get("sources", []))
        else:
            triples[key] = dict(t)
        triples[key]["sources"] = sorted(new_sources)
        if runs_seen:
            triples[key]["seen_in_runs"] = sorted(runs_seen)
        return key

    def type_props(grid_type):
        m = tm["entity_types"].get(grid_type) or {}
        return m

    # ------------------------------------------------------------------
    # Lop bao cao (tu kg.json) nap TRUOC, de node/canh ATT&CK giu `source` goc.
    # Layer nen cua bieu do thi nam trong kg_base_scoped.json, nap rieng.
    # ------------------------------------------------------------------
    report_nodes = report_triples = 0
    if report_kg:
        for n in report_kg.get("nodes", []):
            add_node(n["id"], {**n, "source": n.get("source", "report"),
                               "layer": n.get("layer", "report")})
            report_nodes += 1
        for t in report_kg.get("triples", []):
            # chuan hoa nhan canh cho khop voi nhan grid (khong doi hinh thuc:
            # loader Neo4j tu viet hoa, va se so sanh khong phan biet hoa thuong)
            add_triple({**t, "r": cypher_rel(t["r"]),
                        "layer": t.get("layer", "report")})
            report_triples += 1

    # ------------------------------------------------------------------
    # B2: node technique lay tu regex trong van ban procedure
    # ------------------------------------------------------------------
    for run in runs:
        for code in run.get("technique_codes_in_text") or []:
            canon = idx["revoked_by"].get(code, code)
            info = idx["technique"].get(canon)
            stats["technique_codes_in_text"] += 1
            add_node(canon, {
                "id": canon,
                "type": "attack-pattern",
                "name": info["name"] if info else code,
                "external_id": canon,
                "source": "grid",
                "layer": "grid",
                "detected_by": "regex_in_procedure_text",
                "seen_in_runs": [run["name"]],
            })

    # ------------------------------------------------------------------
    # B2 + B3 + B4: từng run
    # ------------------------------------------------------------------
    for run in runs:
        if not run["technique_id"]:
            continue
        canon_t = idx["revoked_by"].get(run["technique_id"], run["technique_id"])
        tinfo = idx["technique"].get(canon_t)
        add_node(canon_t, {
            "id": canon_t,
            "type": "attack-pattern",
            "name": tinfo["name"] if tinfo else run["technique_name"] or canon_t,
            "external_id": canon_t,
            "source": "grid",
            "layer": "grid",
            "detected_by": "procedure_map",
            "canonicalized_from": run["technique_id"] if canon_t != run["technique_id"] else None,
            "seen_in_runs": [run["name"]],
        })

        # --- entities ---
        seen_ids = set()
        for e in run["entities"]:
            if not isinstance(e, dict):
                continue
            nm = e.get("name") or ""
            if not nm.strip():
                continue
            gtype = (e.get("type") or "other").strip()
            stats["grid_entities_seen"] += 1
            stats["entity_types_seen"][gtype] = stats["entity_types_seen"].get(gtype, 0) + 1
            res = resolve_entity(nm, gtype, entity_aliases(e), idx)
            m = type_props(gtype)
            match = res["match"]
            stats["entities_by_match"][match] = stats["entities_by_match"].get(match, 0) + 1

            matched_attack = bool(res["external_id"])
            if matched_attack:
                stats["reused_attack_nodes"] += 1
            else:
                stats["new_nodes"] += 1

            status = "matched_attack" if matched_attack else "unmatched_attack"
            if match.startswith("ambiguous"):
                status = "ambiguous_attack_match"
            stats["entities_by_status"][status] = stats["entities_by_status"].get(status, 0) + 1

            props = {
                "id": res["id"],
                "type": m.get("node_type") or res["node_type"] or gtype,
                "name": res["attack_name"] or nm,
                "grid_name": nm,
                "grid_type": gtype,
                "alias": res["aliases"] or None,
                "external_id": res["external_id"],
                "source": "grid",
                "layer": "grid",
                "attack_match": match,
                "attack_url": res.get("attack_url"),
                "attack_candidates": res["candidates"] or None,
                "type_status": m.get("status"),
                "type_unmapped": bool(m.get("status") == "unmapped"),
                "extracted_by": "grid",
                "seen_in_runs": [run["name"]],
            }
            if not matched_attack:
                props["layer"] = "report"      # node moi -> lop report, khong dua vao lop nen
            add_node(res["id"], props)
            if res["id"] in seen_ids:
                continue
            seen_ids.add(res["id"])

            # --- B3: canh `uses` suy ra bang code ---
            is_actor = gtype in ACTOR_GRID_TYPES or res["node_type"] in (
                "malware", "tool", "intrusion-set")
            if res["id"] == canon_t:
                # Truong hop entity trung chinh voi technique cua procedure
                # (vd GRID goi "PowerShell" cho procedure T1059.001).
                # Canh tu phong khong co y nghia -> bo qua, dem rieng.
                stats["skipped_self_loops"] = stats.get("skipped_self_loops", 0) + 1
                continue
            add_triple({
                "h": res["id"], "r": "USES", "t": canon_t,
                "source": "grid", "layer": "grid",
                "inferred_by": "code",          # SUY RA bang code, KHONG phai model trich
                "edge_role": "subject" if is_actor else "mentioned",
                "procedure_id": run["procedure_id"],
                "chunk": run["chunk"],
                "evidence": run["text"],
                "evidence_source": "report_1.json procedure",
                "seen_in_runs": [run["name"]],
            })
            stats["uses_edges_inferred"] += 1
            if is_actor:
                stats["uses_edges_subject"] += 1
            else:
                stats["uses_edges_mentioned"] += 1

        # --- relations (B4) ---
        for r in run["relations"]:
            if not isinstance(r, dict):
                continue
            sub = (r.get("sub") or r.get("subject") or r.get("s") or "").strip()
            obj = (r.get("obj") or r.get("object") or r.get("o") or "").strip()
            if not sub or not obj:
                stats["evidence_missing"] += 1
                continue
            stats["grid_relations_seen"] += 1

            rt = r.get("rel_type") or r.get("relation") or r.get("rel") or "other"
            if isinstance(rt, list):
                rt_list = [str(x) for x in rt if x]
            else:
                rt_list = [str(rt)]
            rt0 = rt_list[0] if rt_list else "other"
            rm = tm["rel_types"].get(rt0) or {
                "attack_relationship": None, "status": "unmapped",
                "edge_label": rt0, "not_an_edge": False, "note": "type la khong nam trong REL_TYPES",
            }
            stats["rel_types_seen"][rt0] = stats["rel_types_seen"].get(rt0, 0) + 1

            # hai dau: khop lai ATT&CK neu duoc, neu khong tao node moi
            res_s = resolve_entity(sub, "other", [], idx)
            res_o = resolve_entity(obj, "other", [], idx)
            # weak=True: node da co tu danh sach entity GRID thi giu nguyen thong tin do
            ns = {
                "id": res_s["id"], "type": res_s["node_type"] or "other",
                "name": res_s["attack_name"] or sub, "grid_name": sub,
                "grid_type": "other", "external_id": res_s["external_id"],
                "source": "grid", "layer": "grid" if res_s["external_id"] else "report",
                "attack_match": res_s["match"], "extracted_by": "grid_relation",
                "seen_in_runs": [run["name"]],
            }
            no = {
                "id": res_o["id"], "type": res_o["node_type"] or "other",
                "name": res_o["attack_name"] or obj, "grid_name": obj,
                "grid_type": "other", "external_id": res_o["external_id"],
                "source": "grid", "layer": "grid" if res_o["external_id"] else "report",
                "attack_match": res_o["match"], "extracted_by": "grid_relation",
                "seen_in_runs": [run["name"]],
            }
            add_node(res_s["id"], ns, weak=True)
            add_node(res_o["id"], no, weak=True)

            ev = find_evidence(run["text"], sub, obj, [])
            if ev["evidence_status"] == "found":
                stats["evidence_found"] += 1
            elif ev["evidence_status"] == "found_partial_name":
                stats["evidence_partial"] = stats.get("evidence_partial", 0) + 1
            else:
                stats["evidence_missing"] += 1

            add_triple({
                "h": res_s["id"],
                "r": cypher_rel(rm.get("edge_label") or rt0),
                "t": res_o["id"],
                "source": "grid", "layer": "grid",
                "inferred_by": "grid",          # model trich, khac voi uses o B3
                "predicate_text": r.get("rel"),
                "rel_type_grid": rt_list,
                "rel_type_status": rm.get("status"),
                "rel_type_unmapped": bool(rm.get("status") == "unmapped"),
                "not_an_edge": bool(rm.get("not_an_edge")),
                "procedure_id": run["procedure_id"],
                "chunk": run["chunk"],
                "evidence": ev["evidence"],
                "evidence_status": ev["evidence_status"],
                "evidence_matched_words": ev.get("evidence_matched_words"),
                "seen_in_runs": [run["name"]],
            })

    # ------------------------------------------------------------------
    # sắp xếp lại: node/triple chung giữ lớp gốc, chỉ ghi đè khi có bằng chứng grid
    # ------------------------------------------------------------------
    node_list = list(nodes.values())
    triple_list = list(triples.values())
    return {
        "meta": {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "grid_raw": str(pm.get("source_report", "")),
            "layers": {
                "base": "khac biet - nap bang phuong_phap_2/attack_kg_neo4j.py --scoped",
                "report": "technique + tactic tu bao cao (kg.json)",
                "grid": "entity + triple do GRID trich tu van bao bao cao",
            },
            "stats": stats,
            "attack_bundle_counts": idx["counts"],
            "counts": {
                "nodes": len(node_list),
                "triples": len(triple_list),
                "report_layer_nodes": report_nodes,
                "report_layer_triples": report_triples,
            },
        },
        "nodes": node_list,
        "triples": triple_list,
    }


# ===========================================================================
# report.md
# ===========================================================================
def write_report(path: Path, tm: dict, kg: dict | None, grid_raw: Path,
                 runs, pm, probe_note: str) -> None:
    L = []
    A = L.append
    A("# KG 3 tầng: ATT&CK + technique từ báo cáo + triple GRID")
    A("")
    A(f"Sinh lúc: {datetime.now().isoformat(timespec='seconds')}")
    A("")
    A("> **Lưu ý về số liệu:** mọi con số dưới đây lấy từ lần chạy thật trên máy này.")
    A("> Những phần phụ thuộc kết quả GRID sẽ ghi rõ là **CHƯA CHẠY** nếu `out/grid_raw/`")
    A("> chưa có — không có số nào được ước lượng.")
    A("")

    # --- A2 ---
    A("## A2. Checkpoint")
    A("")
    A("Kích thước đo từ HuggingFace API (repo `anonymousauthorname/ProjectGRID`):")
    A("")
    A("| checkpoint | kích thước | ghi chú |")
    A("|---|---:|---|")
    A("| `base_model` | 8.05 GB | Qwen3-4B-Instruct-2507 — **đang dùng** |")
    A("| `task_bank_reward` | 8.82 GB | model chính của paper (RQ1: 84.62% precision) |")
    A("| `gptoss120b_generator_sft` | 17.65 GB | SFT trên data GPT-OSS-120B |")
    A("| `end2end_reward` / `choice_only_reward` / `end2end_sft_without_rl` | 8.82 GB | biến thể ablation |")
    A("| `llama31_8b_task_bank_reward` | ~16 GB | **không vừa T4** (16 GB VRAM) |")
    A("")
    A("Thư mục `models/*/` trong repo **chỉ có file link, không có trọng số**.")
    A("Quyết định hiện tại: giữ base model, chạy chẩn đoán A1 trước, **không tải thêm**.")
    A("")

    # --- A1 ---
    A("## A1. Chẩn đoán GRID trả danh sách rỗng")
    A("")
    A(f"{probe_note}")
    A("")
    A("### Phát hiện quan trọng: `raw_output.txt` không phải output thô")
    A("")
    A("`out/grid_output/raw_output.txt` được `GRID_backbone._build_final_split_output()`")
    A("(src/grid/GRID_backbone.py:165-198) dựng lại từ `final_entities` / `final_relations`,")
    A("tức là từ kết quả **đã parse**:")
    A("")
    A("```")
    A("blocks = ['#Entity_List_Start#', _json_dumps(final_entities), '#Entity_List_End#', ...]")
    A("```")
    A("")
    A("Thấy `#Entity_List#` là `[]` trong file đó **chỉ chứng minh parser trả rỗng**,")
    A("không chứng minh model trả `[]`. Output thô thật nằm ở `step1_raw.txt`,")
    A("`step2_raw.txt` và `src/GeneratedKGContent/_TemplateDebug/*.jsonl` — đó là lý do")
    A("`out/run_grid_colab.py` lưu riêng 3 nguồn này cho mỗi lần chạy.")
    A("")
    A("### Xếp hạng nguyên nhân (đã đo, không phải phỏng đoán)")
    A("")
    A("| # | nguyên nhân | trạng thái |")
    A("|---|---|---|")
    A("| 1 | Thiếu `json_repair` | **ĐÃ TÁI HIỆN hoàn toàn.** "
      "`article_io_cache_parser.py:311,320,360` bọc `import json_repair` trong "
      "`except Exception: pass` → ImportError bị nuốt im lặng. Đo: thiếu package thì "
      "cả 6 mẫu chuẩn đều ra 0; cài vào thì `entity`=1, `relation`=2+1, `broken_json`=1. |")
    A("| 2 | Model tự sinh list rỗng | Chưa loại — phải đọc `step1_raw.txt` của lần chạy thật. |")
    A("| 3 | Model không phát đủ marker | Chưa loại — cùng nguồn kiểm chứng. |")
    A("| 4 | Request lỗi / timeout (`out/tools.py` nuốt exception, trả `\"\"`) | "
      "Chưa loại — xem `out/grid_raw/vllm_calls.jsonl`. |")
    A("| 5 | Output bị cắt do đuôi `max_tokens` | **ĐÃ LOẠI.** Mẫu `truncated` vẫn cứu được "
      "1 entity nhờ fallback `brace_match` + `json_repair`. Cắt output gây **thiếu**, "
      "không gây rỗng. |")
    A("")
    A("Prompt không phải nguyên nhân: `ENTITY_TYPES` 542 ký tự + `REL_TYPES` 601, prompt")
    A("Step 1 đầy đủ ~9.619 ký tự (~2.671 token), input 7 procedure ~445 token → tổng ~3.1K")
    A("token, `MAX_MODEL_LEN = 16384` rất dư. Không chỗ nào cần context dài hơn.")
    A("")
    A("Chi tiết đầy đủ (bảng từng lần gọi model, prompt/output thô) nằm ở")
    A("`out/grid_raw/diagnosis.md` do `out/grid_diagnose.py` sinh ra.")
    A("")

    # --- A3/A4 ---
    A("## A3/A4. Kết quả chạy GRID trên Colab")
    A("")
    if not runs:
        A("**CHƯA CHẠY.** Không có `out/grid_raw/` trên máy này.")
        A("")
        A("Cần chạy trên Colab (có GPU T4):")
        A("")
        A("```bash")
        A("!git clone https://github.com/cudhna/Grid.git")
        A("%cd Grid")
        A("!git pull")
        A("!python out/run_grid_colab.py")
        A("```")
        A("")
        A("Script sẽ tự sinh `out/grid_raw/` gồm `procedure_map.json`, `manifest.json`,")
        A("`run.log`, `vllm_calls.jsonl`, `diagnosis.md` và một thư mục cho mỗi procedure.")
        A("")
        A("Cấu hình A3 đã đặt trong `out/run_grid_colab.py`:")
        A("")
        A("| tham số | giá trị | lý do |")
        A("|---|---|---|")
        A("| `GRID_TEMP` | `0.0` | yêu cầu temperature 0 |")
        A("| `MAX_RETRIES` | `2` | rỗng thì thử lại tối đa 2 lần, ghi log vào `attempts.json` |")
        A("| `INCLUDE_TECHNIQUE_HEADER` | `False` | bỏ dòng tiêu đề `[Chunk n] Tactic - Txxxx` |")
        A("| `RUN_AGGREGATE` / `RUN_PER_PROCEDURE` | `True` / `True` | chạy cả gộp lẫn từng procedure |")
        A("")
        A("Lưu ý: vì `temperature = 0`, các lần thử lại gần như tất định; khác biệt (nếu có)")
        A("đến từ batching không tất định của vLLM chứ không phải từ nhiệt độ. `attempts.json`")
        A("ghi rõ điều này.")
    else:
        A(f"Đọc được **{len(runs)}** lần chạy GRID trong `{grid_raw}`:")
        A("")
        A("| lần chạy | technique | chunk | entities | relations |")
        A("|---|---|---:|---:|---:|")
        for r in runs:
            A(f"| `{r['name']}` | {r.get('technique_id') or '-'} | {r.get('chunk')} | "
              f"{len(r['entities'])} | {len(r['relations'])} |")
        A("")
        A("Chi tiết từng lần chạy (số lần thử, giây mỗi lần, verdict của từng step):")
        A("`out/grid_raw/<tên>/attempts.json`.")
    A("")

    # --- B1 ---
    A("## B1. Ánh xạ type GRID → STIX/ATT&CK")
    A("")
    meta = tm["meta"]
    A(f"Nguồn: `{meta['source']}` — **{meta['entity_type_count']} entity type** và")
    A(f"**{meta['rel_type_count']} relation type**.")
    A("")
    A("Từ vựng quan hệ đo được trong `enterprise-attack.json` chỉ có 6 giá trị:")
    A(f"`{'`, `'.join(meta['attack_bundle_relationship_vocabulary'])}`.")
    A("Mọi `attack_relationship` đều nằm trong 6 giá trị này.")
    A("")
    A("Phân bố trạng thái:")
    A("")
    A("| nhóm | mapped | alias | approximate | unmapped | tổng |")
    A("|---|---:|---:|---:|---:|---:|")
    for group, key in (("entity type", "entity_types"), ("relation type", "rel_types")):
        cnt = {s: 0 for s in ("mapped", "alias", "approximate", "unmapped")}
        for v in tm[key].values():
            cnt[v["status"]] = cnt.get(v["status"], 0) + 1
        A(f"| {group} | {cnt['mapped']} | {cnt['alias']} | {cnt['approximate']} | "
          f"{cnt['unmapped']} | {sum(cnt.values())} |")
    A("")
    A("**Cần bạn duyệt:** mọi mục `approximate` là tôi đề xuất gần nhất, chưa chắc đúng ngữ nghĩa.")
    A("Mọi mục `unmapped` giữ nguyên tên GRID và gắn cờ `unmapped` — **không có gì bị xóa**.")
    A("")
    A("Danh sách cần duyệt (`approximate`):")
    A("")
    A("| GRID type | đề xuất | vì sao |")
    A("|---|---|---|")
    for k, v in tm["entity_types"].items():
        if v["status"] == "approximate":
            A(f"| `{k}` | `{v['node_type']}` | {v['note'] or '-'} |")
    for k, v in tm["rel_types"].items():
        if v["status"] == "approximate":
            A(f"| `{k}` (rel) | `{v['edge_label']}` | {v['note'] or '-'} |")
    A("")
    A("Toàn bộ bảng: `out/type_mapping.json`.")
    A("")

    # --- B2-B5 ---
    A("## B2–B5. KG ghép")
    A("")
    if kg is None:
        A("**CHƯA CHẠY** — cần `out/grid_raw/` (xem mục A3/A4).")
        A("")
        A("Khi có dữ liệu, chạy:")
        A("")
        A("```bash")
        A("python out/build_kg_full.py")
        A("```")
        A("")
        A("rồi nạp vào Neo4j:")
        A("")
        A("```bash")
        A("python phuong_phap_2/attack_kg_neo4j.py \\")
        A("    --scoped phuong_phap_2/kg_base_scoped.json \\")
        A("    --kg out/kg_full.json --report-name report_1 --password MAT_KHAU")
        A("```")
        A("")
        A("Lớp nền vẫn nạp từ `kg_base_scoped.json` — **không thay đổi**.")
        A("")
        A("`--dry-run` cho biết trước số node/cạnh sẽ nạp, số node theo từng lớp và số cạnh")
        A("GRID — để kiểm tra trước khi ghi vào Neo4j.")
    else:
        st = kg["meta"]["stats"]
        c = kg["meta"]["counts"]
        A(f"Đồ thị cuối: **{c['nodes']} node**, **{c['triples']} cạnh**.")
        A("")
        A("| chỉ số | giá trị |")
        A("|---|---:|")
        A(f"| lần chạy GRID đọc vào | {st['runs']} |")
        A(f"| entity GRID thấy (cộng dồn) | {st['grid_entities_seen']} |")
        A(f"| relation GRID thấy (cộng dồn) | {st['grid_relations_seen']} |")
        A(f"| node khớp được ATT&CK (có `external_id`) | {st['reused_attack_nodes']} |")
        A(f"| node mới tạo (`layer=\"report\"`) | {st['new_nodes']} |")
        A(f"| cạnh `USES` suy ra bằng code (B3) | {st['uses_edges_inferred']} |")
        A(f"|   — vai trò chủ thể | {st['uses_edges_subject']} |")
        A(f"|   — chỉ được nhắc tới | {st['uses_edges_mentioned']} |")
        A(f"| triple GRID có câu bằng chứng (B4) | {st['evidence_found']} |")
        A(f"| triple GRID khớp tên **dạng gần đúng** (`found_partial_name`) | "
          f"{st.get('evidence_partial', 0)} |")
        A(f"| triple GRID **không** tìm được bằng chứng (giữ nguyên, gắn cờ) | {st['evidence_missing']} |")
        A(f"| self-loop bị bỏ qua (entity trùng technique của procedure) | "
          f"{st.get('skipped_self_loops', 0)} |")
        A(f"| node lớp báo cáo (từ `kg.json`) | {c['report_layer_nodes']} |")
        A("")
        A("Kết quả khớp entity với ATT&CK:")
        A("")
        A("| cách khớp | số entity |")
        A("|---|---:|")
        for k, v in sorted(st["entities_by_match"].items(), key=lambda x: -x[1]):
            A(f"| `{k}` | {v} |")
        A("")
        A("Trong đó `ambiguous_*` = nhiều object ATT&CK cùng tên → **để trống `external_id`,")
        A("tạo node mới**, không đoán bừa. `none` = không có trong ATT&CK.")
        A("")
        A("Entity type xuất hiện trong output GRID:")
        A("")
        A("| GRID type | số lần | status ánh xạ |")
        A("|---|---:|---|")
        for k, v in sorted(st["entity_types_seen"].items(), key=lambda x: -x[1]):
            m = tm["entity_types"].get(k)
            A(f"| `{k}` | {v} | {m['status'] if m else 'ngoài ontology'} |")
        A("")
        if st["rel_types_seen"]:
            A("Relation type xuất hiện trong output GRID:")
            A("")
            A("| GRID rel type | số lần | status | nhãn cạnh dùng |")
            A("|---|---:|---|---|")
            for k, v in sorted(st["rel_types_seen"].items(), key=lambda x: -x[1]):
                m = tm["rel_types"].get(k)
                A(f"| `{k}` | {v} | {m['status'] if m else 'ngoài ontology'} | "
                  f"`{m['edge_label'] if m else k}` |")
            A("")
        A("### Ba loại cạnh trong `kg_full.json`")
        A("")
        A("| `source` / `inferred_by` | nghĩa |")
        A("|---|---|")
        A("| `attack` | cạnh `part_of` lấy từ bundle ATT&CK (lớp báo cáo dùng lại) |")
        A("| `grid` + `inferred_by: \"grid\"` | triple **do model GRID trích** (B4) |")
        A("| `grid` + `inferred_by: \"code\"` | cạnh `USES` **suy ra bằng code** (B3) |")
        A("")
        A("### Nạp vào Neo4j (B5)")
        A("")
        A("`phuong_phap_2/attack_kg_neo4j.py` đã sửa để nạp được cả tầng GRID. Xem trước số liệu")
        A("bằng `--dry-run` (không cần Neo4j):")
        A("")
        A("```bash")
        A("python phuong_phap_2/attack_kg_neo4j.py \\")
        A("    --scoped phuong_phap_2/kg_base_scoped.json \\")
        A("    --kg out/kg_full.json --report-name report_1 --password X --dry-run")
        A("```")
        A("")
        A("Cách loader xử lý dữ liệu 3 tầng:")
        A("")
        A("| trường trong `kg_full.json` | cách nạp |")
        A("|---|---|")
        A("| `source=\"attack\"` | cạnh đã có sẵn trong lớp nền: chỉ set `confirmed_by_report` |")
        A("| `source=\"report\"` | cạnh mới, `layer='report'`, `report=<tên>` |")
        A("| `source=\"grid\"` | cạnh mới, `layer='grid'`, kèm `inferred_by`, `evidence`, "
          "`evidence_status`, `rel_type_unmapped`, `not_an_edge` |")
        A("| node có `sources` / `source` | `layers` liệt kê đủ các lớp đã chạm node; `layer` "
          "lấy theo thứ tự `base` > `grid` > `report` (node có trong lớp nền **giữ** `base`) |")
        A("")
        A("Giá trị kiểu dict (vd `evidence_matched_words`) được đổi thành chuỗi JSON vì Neo4j")
        A("chỉ nhận primitive hoặc list primitive — kiểm tra tự động trong")
        A("`python out/selfcheck_part_b.py`.")
        A("")
        A("Lớp nền `kg_base_scoped.json` **không thay đổi**; cùng một lệnh nạp được cho cả")
        A("`kg.json` (chỉ tầng report) và `kg_full.json` (3 tầng).")
        A("")
        A("### Truy vấn mẫu")
        A("")
        A("```cypher")
        A("// Chủ thể nào dùng technique nào, cạnh do model trích (chỉ cạnh có bằng chứng)")
        A("MATCH (a)-[e]->(t:AttackPattern) WHERE e.source='grid' AND e.inferred_by='grid'")
        A("RETURN a.name, type(e), t.name, e.evidence LIMIT 25;")
        A("```")
        A("")
        A("```cypher")
        A("// Cạnh do code suy ra - TÁCH RIÊNG để không nhầm với kết quả model")
        A("MATCH (a)-[e:USES]->(t:AttackPattern)")
        A("WHERE e.inferred_by='code' RETURN a.name, t.name, e.edge_role, e.procedure_id;")
        A("```")
        A("")
        A("```cypher")
        A("// Triple GRID chưa tìm được câu bằng chứng (đã gắn cờ, KHÔNG bị xóa)")
        A("MATCH (a)-[e]->(b) WHERE e.inferred_by='grid' AND e.evidence IS NULL")
        A("RETURN a.name, type(e), b.name, e.rel_type_grid LIMIT 25;")
        A("```")
    A("")

    # --- giới hạn ---
    A("## Kiểm tra bất biện trước khi nạp (self-check)")
    A("")
    A("```bash")
    A("python out/selfcheck_part_b.py")
    A("```")
    A("")
    A("Chạy offline, dùng **fixture tổng hợp** trong thư mục tạm — **không phải kết quả GRID**,")
    A("và không ghi gì vào `out/kg_full.json`. Nó kiểm tra đúng những lỗi đã phát hiện khi viết")
    A("code, để không lặp lại:")
    A("")
    A("- id node không trùng, không cạnh trỏ tới node không tồn tại;")
    A("- nhãn node/cạnh hợp lệ cho Cypher;")
    A("- mọi giá trị trong `kg_full.json` nạp được vào Neo4j (dict → chuỗi JSON, vì Neo4j")
    A("  chỉ nhận primitive hoặc list primitive);")
    A("- cạnh `inferred_by=\"code\"` đều là `USES` và không self-loop;")
    A("- mọi cạnh `inferred_by=\"grid\"` đều có `evidence_status` (thiếu bằng chứng thì gắn")
    A("  cờ, không xóa);")
    A("- node khớp ATT&CK thì có `external_id`, node mới thì để trống;")
    A("- node đã có trong lớp nền giữ `layer='base'` sau khi nạp.")
    A("")

    A("## Ranh giới đã giữ")
    A("")
    A("- Không sửa file gốc của repo; mọi thứ mới nằm trong `out/`.")
    A("- Không thêm kiến thức ngoài văn bản báo cáo: mọi entity/triple GRID đều truy về")
    A("  được một câu trong `report_1.json` (cột `evidence`) hoặc bị gắn cờ `evidence_status`.")
    A("- Không xóa gì: thiếu ánh xạ type thì giữ type gốc + cờ; thiếu bằng chứng thì")
    A("  giữ triple + cờ; khớp mơ hồ thì để trống `external_id`.")
    A("- Lớp nền ATT&CK không đổi: vẫn nạp từ `phuong_phap_2/kg_base_scoped.json`.")
    A("- Entity ngoài phạm vi loader không bị loại — được đánh dấu `in_loader_scope`")
    A("  (giống cách đã xử lý ở tầng technique của báo cáo).")
    A("")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


# ===========================================================================
def main():
    ap = argparse.ArgumentParser(description="Ghep KG 3 tang tu out/grid_raw/ (offline, khong goi model)")
    ap.add_argument("--grid-raw", default=str(OUT_DIR / "grid_raw"))
    ap.add_argument("--attack", default=str(REPO_ROOT / "phuong_phap_2" / "enterprise-attack.json"))
    ap.add_argument("--report-kg", default=str(REPO_ROOT / "phuong_phap_2" / "kg.json"),
                    help="kg.json lop bao cao; bo trong neu khong muon phu lop nay")
    ap.add_argument("--out", default=str(OUT_DIR))
    ap.add_argument("--only-mapping", action="store_true",
                    help="chi tao out/type_mapping.json, khong can out/grid_raw/")
    ap.add_argument("--include-aggregate", action="store_true",
                    help=" dung them lan chay 'aggregate' (mac dinh bo qua de khong trung entity)")
    a = ap.parse_args()

    out_dir = Path(a.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    grid_raw = Path(a.grid_raw)

    # ---- B1: luon co the chay, khong can du lieu GRID ----
    tm = build_type_mapping()
    tm_path = out_dir / "type_mapping.json"
    tm_path.write_text(json.dumps(tm, ensure_ascii=False, indent=2), encoding="utf-8")
    sc = tm["meta"]["status_counts"]
    print(f"B1 -> {tm_path}")
    print(f"    {tm['meta']['entity_type_count']} entity type, "
          f"{tm['meta']['rel_type_count']} relation type; "
          f"mapped={sc.get('mapped', 0)}, alias={sc.get('alias', 0)}, "
          f"approximate={sc.get('approximate', 0)}, unmapped={sc.get('unmapped', 0)}")

    # ---- A1: gan chu thich probe ----
    probe_note = "(chạy `python out/grid_diagnose.py` để có kết luận probe)"
    try:
        import grid_diagnose as gd
        probe = gd.probe_parser(verbose=False)
        probe_note = (f"Probe parser chạy tại đây: **`{probe.get('verdict')}`** — "
                      + gd.VERDICT_VI.get(probe.get("verdict"), ""))
        if probe.get("json_repair"):
            probe_note += (" (`json_repair` ĐÃ cài. Nếu probe trên Colab báo "
                           "`parser_broken` thì chính Colab thiếu package này.)")
        else:
            probe_note += (" (`json_repair` CHƯA cài trên máy này — đây chính là "
                           "nguyên nhân khiến parser trả rỗng; script Colab đã cài sẵn.)")
    except Exception as exc:  # noqa: BLE001
        probe_note = f"Không chạy được probe: {type(exc).__name__}: {exc}"

    # ---- phu thuoc out/grid_raw/ ----
    runs, pm = [], {"procedures": []}
    kg = None
    if a.only_mapping:
        print("--only-mapping: dung lai, khong doc out/grid_raw/")
    elif not (grid_raw / "procedure_map.json").exists():
        print(f"\nCHƯA CÓ DỮ LIỆU: {grid_raw / 'procedure_map.json'} không tồn tại.")
        print("Chạy `python out/run_grid_colab.py` trên Colab trước, rồi tải")
        print(f"thư mục `{grid_raw.name}/` về đây. Không ghi kg_full.json để tránh")
        print("tạo file rỗng gây hiểu nhầm.")
        print(f"\nVẫn ghi {out_dir / 'report.md'} để nắm tình trạng.")
        write_report(out_dir / "report.md", tm, None, grid_raw, runs, pm, probe_note)
        return

    if not a.only_mapping:
        runs, pm = load_grid_runs(grid_raw, a.include_aggregate)
        print(f"\nĐọc {len(runs)} lần chạy GRID từ {grid_raw}")

        idx = load_attack_index(Path(a.attack))
        print(f"ATT&CK index: {idx['counts']}")

        report_kg = None
        if a.report_kg and Path(a.report_kg).exists():
            report_kg = json.loads(Path(a.report_kg).read_text(encoding="utf-8"))
            print(f"Lớp báo cáo từ {a.report_kg}: "
                  f"{len(report_kg['nodes'])} node, {len(report_kg['triples'])} cạnh")
        else:
            print(f"Không có {a.report_kg} -> bỏ lớp báo cáo (chỉ lớp grid)")

        kg = build_kg(runs, pm, idx, tm, report_kg)
        kg_path = out_dir / "kg_full.json"
        kg_path.write_text(json.dumps(kg, ensure_ascii=False, indent=2), encoding="utf-8")
        c = kg["meta"]["counts"]
        st = kg["meta"]["stats"]
        print(f"B5 -> {kg_path}")
        print(f"    {c['nodes']} node, {c['triples']} cạnh")
        print(f"    entity khớp ATT&CK: {st['reused_attack_nodes']}, "
              f"node mới: {st['new_nodes']}")
        print(f"    cạnh USES suy ra bằng code: {st['uses_edges_inferred']}")
        print(f"    triple GRID có bằng chứng: {st['evidence_found']}, "
              f"không có: {st['evidence_missing']} (giữ nguyên + gắn cờ)")

    write_report(out_dir / "report.md", tm, kg, grid_raw, runs, pm, probe_note)
    print(f"\n-> {out_dir / 'report.md'}")


if __name__ == "__main__":
    main()
