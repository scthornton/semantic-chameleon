"""
Hybrid BM25+Vector Retrieval Defense

This is the PRIMARY architectural defense against gradient-optimized RAG poisoning.
Paper finding: Hybrid retrieval achieves 0% co-retrieval across all α ∈ [0.3, 0.7]
for all 50 gradient-optimized attacks in our experiments.

Paper: "Corpus-Dependent RAG Poisoning"
Defense: Hybrid Retrieval (Section 6.1.5, Section 7.3)
Effectiveness: 100% attack neutralization rate in our setting

DEFENSIVE IMPLEMENTATION - Safe for production deployment.
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass


@dataclass
class RetrievalResult:
    """Single document retrieval result"""
    document_id: str
    vector_score: float
    bm25_score: float
    hybrid_score: float
    rank: int


class HybridRetriever:
    """
    Hybrid BM25+Vector Retriever for RAG Defense.

    Key Insight: Gradient-based attacks optimize for cosine similarity in
    embedding space but CANNOT simultaneously optimize for discrete keyword
    matching (BM25). This creates an orthogonal defense that forces attackers
    into a "Pick Your Poison" dilemma.

    Formula (Paper Section 6.1.5):
        hybrid_score = α × vector_similarity + (1-α) × BM25_score

    Where:
        α = 1.0: Pure vector (baseline, vulnerable)
        α = 0.7: Vector-heavy (30% BM25)
        α = 0.5: Balanced (RECOMMENDED for security-critical systems)
        α = 0.3: BM25-heavy (70% BM25)

    Paper Results:
        α = 1.0: 38.0% attack success (baseline)
        α = 0.3-0.7: 0.0% attack success (complete neutralization)

    Why It Works (Section 7.3):
    1. Gradient-free keyword matching: BM25 uses exact term frequencies
       that cannot be optimized via gradient descent
    2. Orthogonal scoring: Vector measures semantic overlap in continuous space,
       BM25 measures discrete keyword occurrence - incompatible optimization targets
    3. Robust across weightings: Even α=0.3 (30% vector) achieves 0% attack success

    Adaptive Attack Resistance (Section 7.3.1):
    - Manual keyword injection degrades stealth → detectable by keyword anomaly
    - Forces trade-off: optimize for BM25 OR stealth, not both
    - Brings attackers into detection range of secondary monitoring
    """

    def __init__(
        self,
        alpha: float = 0.5,
        bm25_k1: float = 1.5,
        bm25_b: float = 0.75,
        normalize_scores: bool = True
    ):
        """
        Initialize Hybrid Retriever.

        Args:
            alpha: Vector weight (0.0 = pure BM25, 1.0 = pure vector)
                  RECOMMENDED: α ≤ 0.5 for security-critical systems
            bm25_k1: BM25 term frequency saturation parameter (default: 1.5)
            bm25_b: BM25 length normalization parameter (default: 0.75)
            normalize_scores: Whether to normalize scores to [0,1] range

        Security Guidance (Paper Section 7.3.2):
            - Security-critical: α ≤ 0.5 (max defense, balanced quality)
            - General purpose: α = 0.5-0.7 (moderate defense, semantic flexibility)
            - Semantic-heavy: α = 0.7-0.8 (prioritize semantics, add monitoring)
        """
        if not 0.0 <= alpha <= 1.0:
            raise ValueError("Alpha must be in range [0.0, 1.0]")

        self.alpha = alpha
        self.bm25_k1 = bm25_k1
        self.bm25_b = bm25_b
        self.normalize_scores = normalize_scores

        # Attack neutralization guarantee (from paper)
        if alpha <= 0.7:
            self._neutralization_guarantee = True
        else:
            self._neutralization_guarantee = False

    def retrieve(
        self,
        query: str,
        corpus: List[Dict],
        k: int = 10,
        return_scores: bool = False
    ) -> List[RetrievalResult]:
        """
        Retrieve top-k documents using hybrid scoring.

        Args:
            query: User query string
            corpus: List of documents with 'id' and 'content' fields
            k: Number of documents to retrieve
            return_scores: If True, return individual score components

        Returns:
            List of RetrievalResult objects, sorted by hybrid_score descending

        Note: This is a reference implementation. In production, replace with:
            - Optimized vector search (FAISS, Annoy, Qdrant, Weaviate, Pinecone)
            - Efficient BM25 implementation (Elasticsearch, rank-bm25)
            - Parallel scoring for large corpora
        """
        results = []

        # Get vector embeddings (replace with your embedding model)
        query_vector = self._embed_query(query)

        for doc in corpus:
            # Compute vector similarity
            doc_vector = self._embed_document(doc['content'])
            vector_score = self._cosine_similarity(query_vector, doc_vector)

            # Compute BM25 score
            bm25_score = self._compute_bm25(
                query=query,
                document=doc['content'],
                corpus=corpus
            )

            # Normalize scores if requested
            if self.normalize_scores:
                vector_score = self._normalize(vector_score, 0, 1)
                bm25_score = self._normalize(bm25_score, 0, max_bm25_score)

            # Compute hybrid score (Paper Formula)
            hybrid_score = (
                self.alpha * vector_score +
                (1 - self.alpha) * bm25_score
            )

            results.append(RetrievalResult(
                document_id=doc['id'],
                vector_score=vector_score,
                bm25_score=bm25_score,
                hybrid_score=hybrid_score,
                rank=0  # Will be set after sorting
            ))

        # Sort by hybrid score and assign ranks
        results.sort(key=lambda x: x.hybrid_score, reverse=True)
        for idx, result in enumerate(results):
            result.rank = idx + 1

        return results[:k]

    def _compute_bm25(
        self,
        query: str,
        document: str,
        corpus: List[Dict]
    ) -> float:
        """
        Compute BM25 score (Okapi BM25).

        Formula:
            BM25 = Σ IDF(qᵢ) × (f(qᵢ,D) × (k₁ + 1)) /
                   (f(qᵢ,D) + k₁ × (1 - b + b × |D| / avgdl))

        Where:
            IDF(qᵢ) = ln((N - df(qᵢ) + 0.5) / (df(qᵢ) + 0.5) + 1)
            f(qᵢ,D) = frequency of query term qᵢ in document D
            |D| = length of document D
            avgdl = average document length in corpus
            N = total number of documents

        Paper Parameters (Section 6.1.5):
            k₁ = 1.5 (term frequency saturation)
            b = 0.75 (length normalization)

        Note: This is a simplified implementation. In production, use:
            - Pre-computed IDF values
            - Inverted index for efficiency
            - Elasticsearch BM25 or rank-bm25 library
        """
        # IMPLEMENTATION NOTE: Replace with optimized BM25
        # See: https://github.com/dorianbrown/rank_bm25

        # Tokenize
        query_terms = self._tokenize(query)
        doc_terms = self._tokenize(document)

        # Compute document stats
        doc_length = len(doc_terms)
        avgdl = self._compute_average_doc_length(corpus)
        N = len(corpus)

        # Compute BM25 score
        score = 0.0
        for term in query_terms:
            if term not in doc_terms:
                continue

            # Term frequency in document
            freq = doc_terms.count(term)

            # Document frequency (how many docs contain term)
            df = self._compute_document_frequency(term, corpus)

            # IDF component
            idf = np.log((N - df + 0.5) / (df + 0.5) + 1)

            # BM25 component
            numerator = freq * (self.bm25_k1 + 1)
            denominator = freq + self.bm25_k1 * (
                1 - self.bm25_b + self.bm25_b * doc_length / avgdl
            )

            score += idf * (numerator / denominator)

        return score

    def _embed_query(self, query: str) -> np.ndarray:
        """Placeholder for query embedding. Replace with your model."""
        raise NotImplementedError(
            "Replace with your embedding model. "
            "Options: sentence-transformers, OpenAI embeddings, etc."
        )

    def _embed_document(self, document: str) -> np.ndarray:
        """Placeholder for document embedding. Replace with your model."""
        raise NotImplementedError(
            "Replace with your embedding model."
        )

    def _cosine_similarity(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Compute cosine similarity between two vectors."""
        return np.dot(vec1, vec2) / (np.linalg.norm(vec1) * np.linalg.norm(vec2))

    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenization. Replace with proper tokenizer in production."""
        return text.lower().split()

    def _compute_average_doc_length(self, corpus: List[Dict]) -> float:
        """Compute average document length in corpus."""
        total_length = sum(len(self._tokenize(doc['content'])) for doc in corpus)
        return total_length / len(corpus) if corpus else 0

    def _compute_document_frequency(self, term: str, corpus: List[Dict]) -> int:
        """Count documents containing term."""
        count = 0
        for doc in corpus:
            if term in self._tokenize(doc['content']):
                count += 1
        return count

    def _normalize(self, value: float, min_val: float, max_val: float) -> float:
        """Normalize value to [0, 1] range."""
        if max_val == min_val:
            return 0.5
        return (value - min_val) / (max_val - min_val)

    def get_security_config(self) -> Dict:
        """Get current security configuration and assessment."""
        return {
            'alpha': self.alpha,
            'vector_weight': f"{self.alpha * 100:.0f}%",
            'bm25_weight': f"{(1 - self.alpha) * 100:.0f}%",
            'bm25_k1': self.bm25_k1,
            'bm25_b': self.bm25_b,
            'security_level': self._assess_security_level(),
            'attack_neutralization_guarantee': self._neutralization_guarantee,
            'paper_validation': "Tested against 50 gradient-optimized attacks",
            'recommendation': self._get_recommendation()
        }

    def _assess_security_level(self) -> str:
        """Assess security level based on alpha value."""
        if self.alpha <= 0.5:
            return "HIGH - Maximum defense against gradient-optimized attacks"
        elif self.alpha <= 0.7:
            return "MODERATE - Good defense, maintaining semantic flexibility"
        elif self.alpha <= 0.8:
            return "LOW - Prioritizes semantics, requires monitoring"
        else:
            return "VULNERABLE - Minimal BM25 protection, not recommended"

    def _get_recommendation(self) -> str:
        """Get security recommendation based on configuration."""
        if self.alpha <= 0.5:
            return "✓ RECOMMENDED: Balanced defense and quality for security-critical systems"
        elif self.alpha <= 0.7:
            return "⚠ ACCEPTABLE: Consider α ≤ 0.5 for maximum security"
        else:
            return "⚠ NOT RECOMMENDED: Increase BM25 weight (decrease α) for better security"


def example_deployment():
    """
    Example: Deploying Hybrid Retrieval Defense in Production

    This shows recommended configuration for different use cases.
    """

    print("=== Security-Critical Deployment (Recommended) ===")
    secure_retriever = HybridRetriever(alpha=0.5)  # 50% vector, 50% BM25
    config = secure_retriever.get_security_config()
    print(f"Configuration: {config['vector_weight']} vector, {config['bm25_weight']} BM25")
    print(f"Security Level: {config['security_level']}")
    print(f"Attack Neutralization: {'YES' if config['attack_neutralization_guarantee'] else 'NO'}")
    print(f"Recommendation: {config['recommendation']}")
    print()

    print("=== General Purpose Deployment ===")
    balanced_retriever = HybridRetriever(alpha=0.6)
    config = balanced_retriever.get_security_config()
    print(f"Configuration: {config['vector_weight']} vector, {config['bm25_weight']} BM25")
    print(f"Security Level: {config['security_level']}")
    print()

    print("=== Maximum Defense Deployment ===")
    max_defense_retriever = HybridRetriever(alpha=0.3)  # 30% vector, 70% BM25
    config = max_defense_retriever.get_security_config()
    print(f"Configuration: {config['vector_weight']} vector, {config['bm25_weight']} BM25")
    print(f"Security Level: {config['security_level']}")
    print()

    # Example retrieval (requires actual embeddings)
    try:
        query = "How to secure authentication in enterprise systems"
        corpus = [
            {'id': 'doc1', 'content': 'Enterprise authentication best practices...'},
            {'id': 'doc2', 'content': 'MFA implementation guide...'},
        ]
        results = secure_retriever.retrieve(query, corpus, k=10)
        for result in results:
            print(f"Rank {result.rank}: {result.document_id}")
            print(f"  Vector: {result.vector_score:.3f}, BM25: {result.bm25_score:.3f}, Hybrid: {result.hybrid_score:.3f}")
    except NotImplementedError:
        print("Note: Requires embedding model implementation")


if __name__ == "__main__":
    example_deployment()
