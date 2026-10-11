from typing import List, Tuple, Dict, Any, Hashable, Optional, Union


def reciprocal_rank_fusion(
    ranked_lists: Optional[List[Tuple[str, Union[List[Tuple[Hashable, float]], List[Hashable]]]]] = None,
    k: int = 60,
    weights: Optional[Dict[str, float]] = None,
) -> List[Tuple[Hashable, float, Dict[str, int]]]:
    if not ranked_lists:
        return []

    k = max(1, int(k))
    rrf_scores: Dict[Hashable, float] = {}
    rank_details: Dict[Hashable, Dict[str, int]] = {}

    for retriever_tuple in ranked_lists:
        if not retriever_tuple or len(retriever_tuple) < 2:
            continue
        retriever_name, candidates = retriever_tuple[0], retriever_tuple[1]
        if not candidates:
            continue

        weight = max(0.0, float(weights.get(retriever_name, 1.0))) if weights else 1.0
        if weight <= 0.0:
            continue

        seen_in_retriever = set()
        effective_rank = 1

        for item in candidates:
            # Handle both (item_id, score) tuples and bare item_id values
            if isinstance(item, (tuple, list)) and len(item) >= 1:
                item_id = item[0]
            else:
                item_id = item

            # Skip duplicates within the same retriever list (keep the highest rank)
            if item_id in seen_in_retriever:
                continue
            seen_in_retriever.add(item_id)

            reciprocal_score = weight / (k + effective_rank)
            rrf_scores[item_id] = rrf_scores.get(item_id, 0.0) + reciprocal_score

            if item_id not in rank_details:
                rank_details[item_id] = {}
            rank_details[item_id][retriever_name] = effective_rank
            effective_rank += 1

    # Sort descending by RRF score
    sorted_items = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)

    results = []
    for item_id, score in sorted_items:
        results.append((item_id, round(score, 6), rank_details.get(item_id, {})))

    return results
