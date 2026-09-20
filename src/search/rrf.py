from typing import List, Tuple, Dict, Any, Hashable


def reciprocal_rank_fusion(
    ranked_lists: List[Tuple[str, List[Tuple[Hashable, float]]]],
    k: int = 60,
) -> List[Tuple[Hashable, float, Dict[str, int]]]:
    """
    Computes Reciprocal Rank Fusion (RRF) across multiple ranked lists.

    Args:
        ranked_lists: List of (retriever_name, [(item_id, score), ...]) where items are
                      ordered from best (rank 1) to worst.
        k: Smoothing constant (default: 60) to prevent top items from dominating completely.

    Returns:
        Sorted list of tuples: (item_id, rrf_score, {retriever_name: rank_position, ...})
        ordered in descending order of rrf_score.
    """
    rrf_scores: Dict[Hashable, float] = {}
    rank_details: Dict[Hashable, Dict[str, int]] = {}

    for retriever_name, candidates in ranked_lists:
        for rank_zero, (item_id, _) in enumerate(candidates):
            rank = rank_zero + 1  # 1-indexed rank
            reciprocal_score = 1.0 / (k + rank)

            rrf_scores[item_id] = rrf_scores.get(item_id, 0.0) + reciprocal_score

            if item_id not in rank_details:
                rank_details[item_id] = {}
            rank_details[item_id][retriever_name] = rank

    # Sort descending by RRF score
    sorted_items = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)

    results = []
    for item_id, score in sorted_items:
        results.append((item_id, round(score, 6), rank_details.get(item_id, {})))

    return results
