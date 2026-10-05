# Knowledge Base (Supporting Reference Material)

## Architectural Principle

The assets within `knowledge_base/` provide **supporting reference data** for semantic lookups, prompt augmentation, and verification sources.

> [!IMPORTANT]
> **Supporting Knowledge Only**
> - The Knowledge Base is **NOT** authoritative over the runtime `SecurityFact` contract.
> - The runtime pipeline relies on verified deterministic mappings (`backend/app/normalization/cisco.py`) for authoritative facts.
> - Mappings stored here serve as offline semantic reference data and evaluation ground truth.
> - The deterministic compliance engine remains the sole evaluator of compliance state.

## Directory Structure

- `mappings/`: Semantic mapping references linking vendor syntax to canonical security concepts.
- `rules/`: Draft compliance rule specifications with framework attribution (attribution pending official benchmark verification).
- `sources/`: Provenance registry (`source_register.json`) documenting authoritative benchmarks, vendor documentation, and sample repositories.
