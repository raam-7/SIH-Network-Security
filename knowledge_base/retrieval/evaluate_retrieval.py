import json
from sentence_transformers import SentenceTransformer, util

MAPPING_FILE = "knowledge_base/mappings/cisco_verified_mappings.json"
QUERY_FILE = "training/evaluation/retrieval_queries.json"

model = SentenceTransformer("all-MiniLM-L6-v2")

with open(MAPPING_FILE) as f:
    mappings = json.load(f)

unique = {}
for m in mappings:
    unique[m["raw_command"]] = m
mappings = list(unique.values())

texts = [
    f"{m['raw_command']} | {m['security_concept']} | "
    f"{m['property']} | {m['value']}"
    for m in mappings
]

embeddings = model.encode(texts, convert_to_tensor=True)

with open(QUERY_FILE) as f:
    queries = json.load(f)

correct = 0

for item in queries:
    query_embedding = model.encode(item["query"], convert_to_tensor=True)
    scores = util.cos_sim(query_embedding, embeddings)[0]
    best_idx = int(scores.argmax())
    best = mappings[best_idx]

    predicted = best["security_concept"]
    expected = item["expected_concept"]

    if expected is None:
        predicted = None if float(scores[best_idx]) < 0.55 else predicted
        passed = predicted is None
    else:
        passed = predicted == expected

    correct += passed

    print(
        f"{'PASS' if passed else 'FAIL'} | "
        f"score={float(scores[best_idx]):.4f} | "
        f"expected={expected} | predicted={predicted}"
    )

print(f"\nRESULT: {correct}/{len(queries)} passed")
