# Training & Evaluation Data Assets

## 1. Overview & Seed Corpus Status

The JSONL files in this directory contain verified semantic mappings between raw network configuration commands and canonical security concepts:

- `train.jsonl` (7 records)
- `val.jsonl` (4 records)
- `test.jsonl` (9 records)
- **Total: 20 verified seed examples**

> [!IMPORTANT]
> **Seed / Evaluation Corpus Only**
> This collection of 20 examples represents an initial semantic seed and evaluation benchmark.
> It is **NOT** a production training dataset and is **NOT sufficient for machine learning model training or fine-tuning (e.g., LoRA, QLoRA)**.
> Production fine-tuning will require a substantially larger, balanced, multi-vendor dataset with full provenance tracking.

---

## 2. Provenance & Platform Integrity

All records preserve strict provenance metadata:
- `vendor`: Network device vendor (e.g., `"cisco"`).
- `platform`: Specific operating system (explicitly maintaining distinction between `"ios"` and `"ios-xe"`).
- `raw_command`: Unaltered CLI command string.
- `security_concept`: Standardized taxonomy concept.
- `property`: Evaluated attribute.
- `value`: Normalized representation.
- `line_start` / `line_end`: Physical source line numbers.
- `source_file`: Reference configuration in `training/raw/configurations/`.
- `source_type`: Origin classification (e.g., `"verified_vendor_config"`).
- `human_verified`: Boolean indicator of manual review.

Platform labels must strictly distinguish between **Cisco IOS** (e.g., v15.x configurations) and **Cisco IOS-XE** (e.g., v16.x / v17.x configurations). Cisco IOS examples must never be relabeled as IOS-XE.
