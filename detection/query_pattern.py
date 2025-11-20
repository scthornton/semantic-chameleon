"""
Query Pattern Differential Detection

This method detects poisoned documents by analyzing their retrieval patterns
for benign vs. sensitive queries. Malicious documents show differential
retrieval rates - high for attack-related queries, low for benign queries.

Paper: "Corpus-Dependent RAG Poisoning"
Method: Query Pattern Differential (Section 4.4, Method 4)
Performance: Best F1 across both corpora (0.632 FEVER, 0.171 Security SE)

DEFENSIVE USE ONLY - No attack implementations included.
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass


@dataclass
class QueryPatternResult:
    """Result from query pattern differential analysis"""
    document_id: str
    benign_retrieval_rate: float
    sensitive_retrieval_rate: float
    differential_score: float
    is_flagged: bool
    threshold_used: float


class QueryPatternDetector:
    """
    Detects poisoned documents using query pattern differential analysis.

    Key Insight: Malicious documents are optimized to retrieve highly for
    specific attack queries but maintain low retrieval for benign queries.
    This creates a detectable differential pattern.

    Algorithm (Paper Section 4.4):
    1. Generate benign query set (100 queries from corpus)
    2. Generate sensitive query set (20 queries per attack family)
    3. For each document, simulate retrieval against both sets
    4. Compute differential score: max(0, sensitive_rate - benign_rate)
    5. Flag documents exceeding threshold

    Usage:
        detector = QueryPatternDetector(
            benign_queries=sample_from_production_logs(100),
            sensitive_queries=craft_attack_templates(20)
        )
        results = detector.analyze_corpus(corpus, threshold=0.2)
    """

    def __init__(
        self,
        benign_queries: List[str],
        sensitive_queries: List[str],
        embedding_model: Optional[str] = None,
        top_k: int = 10
    ):
        """
        Initialize Query Pattern Detector.

        Args:
            benign_queries: Randomly sampled from corpus document titles/questions
                           Represents typical user information-seeking behavior
            sensitive_queries: Expert-crafted templates covering attack families
                              (auth bypass, data exfil, prompt injection, etc.)
            embedding_model: Embedding model for similarity computation
            top_k: Top-k documents to consider for retrieval

        Note: Quality of detection depends directly on sensitivity of query set.
              Defenders should enumerate attack families relevant to their context.
        """
        self.benign_queries = benign_queries
        self.sensitive_queries = sensitive_queries
        self.embedding_model = embedding_model
        self.top_k = top_k

        # Validated thresholds from paper (Section 6.2.3)
        self.recommended_thresholds = {
            'security_se': 0.20,  # 16.7% TPR, 0.02% FPR, 17.6% Precision
            'fever': 0.15,        # 66.7% TPR, 0.01% FPR, 60.0% Precision
            'general': 0.15       # Default recommendation
        }

    def analyze_corpus(
        self,
        corpus: List[Dict],
        threshold: float = 0.15,
        return_all_scores: bool = False
    ) -> Dict:
        """
        Analyze entire corpus for poisoned documents.

        Args:
            corpus: List of documents with 'id' and 'content' fields
            threshold: Differential score threshold for flagging
            return_all_scores: If True, return scores for all documents

        Returns:
            Dictionary with detection results:
                - flagged_documents: List of QueryPatternResult for flagged docs
                - total_flagged: Count of flagged documents
                - false_positive_estimate: Expected FPR based on corpus type
                - all_scores: (Optional) Scores for all documents
        """
        results = []

        for doc in corpus:
            # Simulate retrieval for benign queries
            benign_retrievals = self._count_retrievals(
                doc, self.benign_queries, self.top_k
            )
            benign_rate = benign_retrievals / len(self.benign_queries)

            # Simulate retrieval for sensitive queries
            sensitive_retrievals = self._count_retrievals(
                doc, self.sensitive_queries, self.top_k
            )
            sensitive_rate = sensitive_retrievals / len(self.sensitive_queries)

            # Compute differential score (Paper Eq. 3)
            differential = max(0, sensitive_rate - benign_rate)

            is_flagged = differential > threshold

            result = QueryPatternResult(
                document_id=doc['id'],
                benign_retrieval_rate=benign_rate,
                sensitive_retrieval_rate=sensitive_rate,
                differential_score=differential,
                is_flagged=is_flagged,
                threshold_used=threshold
            )
            results.append(result)

        flagged = [r for r in results if r.is_flagged]

        output = {
            'flagged_documents': flagged,
            'total_flagged': len(flagged),
            'total_documents': len(corpus),
            'flagging_rate': len(flagged) / len(corpus) if corpus else 0,
            'threshold': threshold,
            'expected_performance': self._get_expected_performance(threshold)
        }

        if return_all_scores:
            output['all_scores'] = results

        return output

    def _count_retrievals(
        self,
        document: Dict,
        queries: List[str],
        top_k: int
    ) -> int:
        """
        Count how many queries retrieve this document in top-k.

        This is a placeholder - actual implementation needs:
        - Embedding model for query and document
        - Similarity computation
        - Ranking mechanism

        In production, replace with your RAG system's retrieval logic.
        """
        # IMPLEMENTATION NOTE: Replace with actual retrieval logic
        # Example:
        # doc_embedding = embed(document['content'])
        # count = 0
        # for query in queries:
        #     query_embedding = embed(query)
        #     similarity = cosine_similarity(query_embedding, doc_embedding)
        #     if similarity in top_k_for_query:
        #         count += 1
        # return count

        raise NotImplementedError(
            "Replace with your retrieval system's implementation. "
            "See docs/REPRODUCIBILITY.md for embedding setup."
        )

    def _get_expected_performance(self, threshold: float) -> Dict:
        """Get expected performance metrics based on paper results (Table in Section 6.2.3)"""
        if threshold == 0.20:
            return {
                'corpus_type': 'Security SE (Technical)',
                'expected_tpr': 0.167,
                'expected_fpr': 0.0002,
                'expected_precision': 0.176,
                'expected_f1': 0.171,
                'note': 'Technical corpora show lower performance but still best available method'
            }
        elif threshold == 0.15:
            return {
                'corpus_type': 'FEVER (General Knowledge)',
                'expected_tpr': 0.667,
                'expected_fpr': 0.0001,
                'expected_precision': 0.600,
                'expected_f1': 0.632,
                'note': 'General knowledge corpora show excellent discrimination'
            }
        else:
            return {
                'note': 'Custom threshold - see paper Section 6.2.3 for calibration guidance'
            }

    def generate_sensitive_queries(
        self,
        attack_families: List[str],
        queries_per_family: int = 20
    ) -> List[str]:
        """
        Generate sensitive query templates for common attack families.

        This provides CONCEPTUAL templates only. Actual queries should be
        tailored to your specific deployment context and threat model.

        Args:
            attack_families: e.g., ['auth_bypass', 'data_exfil', 'prompt_inject']
            queries_per_family: Number of query variants per family

        Returns:
            List of sensitive queries (NON-WEAPONIZED examples)

        IMPORTANT: These are sanitized educational examples.
        In production, craft queries relevant to YOUR specific threats.
        """
        templates = {
            'auth_bypass': [
                # SANITIZED - Real implementation would be more specific
                "authentication security best practices",
                "secure login implementation",
                "access control mechanisms"
            ],
            'data_exfil': [
                # SANITIZED
                "database security practices",
                "data access controls",
                "information security policies"
            ],
            'prompt_inject': [
                # SANITIZED
                "LLM safety guidelines",
                "prompt engineering techniques",
                "AI system security"
            ]
        }

        queries = []
        for family in attack_families:
            if family in templates:
                # In production: expand with synonyms, paraphrasing
                queries.extend(templates[family])

        return queries

    def recommend_threshold(self, corpus_type: str) -> float:
        """
        Recommend threshold based on corpus type.

        Args:
            corpus_type: 'technical' or 'general'

        Returns:
            Recommended threshold value
        """
        if corpus_type.lower() in ['technical', 'security_se', 'code', 'api']:
            return self.recommended_thresholds['security_se']
        else:
            return self.recommended_thresholds['fever']


def example_usage():
    """
    Example usage of Query Pattern Detector.

    This shows the API - actual implementation requires:
    1. Real corpus data
    2. Embedding model setup
    3. Query generation tailored to your threats
    """

    # Step 1: Generate query sets (customize for your deployment)
    benign_queries = [
        # Sample from your production logs or corpus titles
        "How to implement secure authentication",
        "Best practices for database backups",
        # ... 98 more
    ]

    sensitive_queries = [
        # Craft based on YOUR threat model
        # These are sanitized examples
        "enterprise security policies",
        "data protection mechanisms",
        # ... 18 more per attack family
    ]

    # Step 2: Initialize detector
    detector = QueryPatternDetector(
        benign_queries=benign_queries,
        sensitive_queries=sensitive_queries
    )

    # Step 3: Analyze corpus
    corpus = [
        {'id': 'doc1', 'content': 'Legitimate security content...'},
        {'id': 'doc2', 'content': 'Normal database documentation...'},
        # ... more documents
    ]

    # Step 4: Get results
    threshold = detector.recommend_threshold('technical')  # or 'general'
    results = detector.analyze_corpus(corpus, threshold=threshold)

    print(f"Flagged {results['total_flagged']} / {results['total_documents']} documents")
    print(f"Expected FPR: {results['expected_performance']['expected_fpr']:.4f}")

    # Step 5: Review flagged documents (manual verification recommended)
    for doc in results['flagged_documents']:
        print(f"Document {doc.document_id}:")
        print(f"  Benign rate: {doc.benign_retrieval_rate:.3f}")
        print(f"  Sensitive rate: {doc.sensitive_retrieval_rate:.3f}")
        print(f"  Differential: {doc.differential_score:.3f}")


if __name__ == "__main__":
    example_usage()
