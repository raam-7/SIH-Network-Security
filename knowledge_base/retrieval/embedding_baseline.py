import json
from sentence_transformers import SentenceTransformer, util

MAPPING_FILE = "knowledge_base/mappings/cisco_verified_mappings.json"

model = SentenceTransformer("all-MiniLM-L6-v2")

with open(MAPPING_FILE) as f:
    raw_mappings = json.load(f)

unique = {}
for m in raw_mappings:
    unique[m["raw_command"]] = m

mappings = list(unique.values())

texts = [
    f"{m['raw_command']} | {m['security_concept']} | "
    f"{m['property']} | {m['value']}"
    for m in mappings
]

embeddings = model.encode(texts, convert_to_tensor=True)


def retrieve(query, top_k=3):
    query_embedding = model.encode(query, convert_to_tensor=True)
    scores = util.cos_sim(query_embedding, embeddings)[0]

    top_indices = scores.argsort(descending=True)[:top_k]

    results = []

    for idx in top_indices:
        mapping = mappings[int(idx)]
        result = dict(mapping)
        result["score"] = float(scores[idx])
        results.append(result)

    return results


def interactive():
    query = input("Enter Cisco command: ").strip()

    results = retrieve(query)

    best_score = results[0]["score"]

    print(f"\nBest similarity: {best_score:.4f}")

    if best_score < 0.55:
        print("STATUS: UNKNOWN / HUMAN REVIEW")
    else:
        print("STATUS: MATCH FOUND")

    for rank, mapping in enumerate(results, 1):
        print(f"\nRank {rank}")
        print("Score:", round(mapping["score"], 4))
        print("Command:", mapping["raw_command"])
        print("Concept:", mapping["security_concept"])
        print("Property:", mapping["property"])
        print("Value:", mapping["value"])


if __name__ == "__main__":
    interactive()
