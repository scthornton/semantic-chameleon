"""
Semantic Drift Detection

This method detects poisoned documents by identifying anomalous positions
in the corpus embedding space. Malicious documents often cluster together
or occupy outlier regions far from benign content.

Paper: "Corpus-Dependent RAG Poisoning"
Method: Semantic Drift (Section 4.1, Method 1)
Performance: Moderate effectiveness, corpus-dependent (0.226 F1 FEVER, 0.069 Security SE)

DEFENSIVE USE ONLY - No attack implementations included.
"""

import numpy as np
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from sklearn.decomposition import PCA
from sklearn.neighbors import LocalOutlierFactor


@dataclass
class SemanticDriftResult:
    """Result from semantic drift analysis"""
    document_id: str
    distance_to_centroid: float
    lof_score: float
    pca_position: np.ndarray
    is_flagged: bool
    threshold_used: float


class SemanticDriftDetector:
    """
    Detects poisoned documents using embedding space anomaly detection.

    Key Insight: Gradient-optimized attack documents often occupy unusual
    positions in embedding space - either clustered together (if from same
    attack) or isolated from benign content (if semantically distant from
    corpus domain).

    Algorithm (Paper Section 4.1):
    1. Compute embeddings for all corpus documents
    2. Apply dimensionality reduction (PCA) for visualization
    3. Compute Local Outlier Factor (LOF) scores
    4. Flag documents exceeding threshold

    Limitations (Paper Section 6.2.1):
    - Corpus-dependent: Works best on uniform semantic spaces (FEVER)
    - Technical corpora show poor discrimination (Security SE: F1=0.069)
    - Attack documents may blend into diverse technical spaces
    - Not recommended as sole detection method for technical domains

    Usage:
        detector = SemanticDriftDetector(embedding_model="sentence-transformers/all-MiniLM-L6-v2")
        results = detector.analyze_corpus(corpus, threshold=2.0)
    """

    def __init__(
        self,
        embedding_model: Optional[str] = None,
        n_neighbors: int = 20,
        contamination: float = 0.01,
        pca_components: int = 50
    ):
        """
        Initialize Semantic Drift Detector.

        Args:
            embedding_model: Name/path of embedding model to use
            n_neighbors: Number of neighbors for LOF computation (default: 20)
            contamination: Expected proportion of outliers (default: 0.01 = 1%)
            pca_components: Number of PCA components for dimensionality reduction

        Note: LOF algorithm expects contamination parameter to calibrate threshold.
              Set conservatively (0.01-0.05) to minimize false positives.
        """
        self.embedding_model = embedding_model
        self.n_neighbors = n_neighbors
        self.contamination = contamination
        self.pca_components = pca_components

        # Validated thresholds from paper (Section 6.2.1)
        self.recommended_thresholds = {
            'security_se': 1.5,   # 16.7% TPR, 0.01% FPR (poor discrimination)
            'fever': 2.0,         # 50.0% TPR, 0.004% FPR (moderate performance)
            'general': 2.0        # Default recommendation
        }

    def analyze_corpus(
        self,
        corpus: List[Dict],
        threshold: float = 2.0,
        return_all_scores: bool = False
    ) -> Dict:
        """
        Analyze entire corpus for poisoned documents using semantic drift.

        Args:
            corpus: List of documents with 'id' and 'content' fields
            threshold: LOF score threshold for flagging (higher = more outlier)
            return_all_scores: If True, return scores for all documents

        Returns:
            Dictionary with detection results:
                - flagged_documents: List of SemanticDriftResult for flagged docs
                - total_flagged: Count of flagged documents
                - corpus_uniformity: Measure of semantic cohesion (lower = more diverse)
                - expected_performance: Expected TPR/FPR based on corpus type
                - all_scores: (Optional) Scores for all documents
        """
        # Step 1: Compute embeddings for all documents
        embeddings = self._compute_embeddings(corpus)

        # Step 2: Compute corpus centroid
        centroid = np.mean(embeddings, axis=0)

        # Step 3: Apply PCA for dimensionality reduction
        pca = PCA(n_components=min(self.pca_components, len(corpus), embeddings.shape[1]))
        embeddings_reduced = pca.fit_transform(embeddings)

        # Step 4: Compute Local Outlier Factor scores
        lof = LocalOutlierFactor(
            n_neighbors=min(self.n_neighbors, len(corpus) - 1),
            contamination=self.contamination,
            novelty=False
        )
        lof_scores = -lof.fit_predict(embeddings_reduced)  # Negative = outlier

        # Step 5: Analyze each document
        results = []
        for idx, doc in enumerate(corpus):
            # Distance to corpus centroid
            distance = np.linalg.norm(embeddings[idx] - centroid)

            # LOF score (higher = more outlier)
            lof_score = -lof.negative_outlier_factor_[idx]

            is_flagged = lof_score > threshold

            result = SemanticDriftResult(
                document_id=doc['id'],
                distance_to_centroid=float(distance),
                lof_score=float(lof_score),
                pca_position=embeddings_reduced[idx],
                is_flagged=is_flagged,
                threshold_used=threshold
            )
            results.append(result)

        flagged = [r for r in results if r.is_flagged]

        # Compute corpus uniformity (lower = more semantically diverse)
        distances = [r.distance_to_centroid for r in results]
        corpus_uniformity = float(np.std(distances) / np.mean(distances))

        output = {
            'flagged_documents': flagged,
            'total_flagged': len(flagged),
            'total_documents': len(corpus),
            'flagging_rate': len(flagged) / len(corpus) if corpus else 0,
            'threshold': threshold,
            'corpus_uniformity': corpus_uniformity,
            'pca_variance_explained': float(np.sum(pca.explained_variance_ratio_)),
            'expected_performance': self._get_expected_performance(threshold, corpus_uniformity)
        }

        if return_all_scores:
            output['all_scores'] = results

        return output

    def _compute_embeddings(self, corpus: List[Dict]) -> np.ndarray:
        """
        Compute embeddings for all documents in corpus.

        This is a placeholder - actual implementation needs:
        - Embedding model (sentence-transformers, OpenAI, etc.)
        - Batching for large corpora
        - GPU acceleration if available

        In production, replace with your embedding infrastructure.
        """
        # IMPLEMENTATION NOTE: Replace with actual embedding model
        # Example:
        # from sentence_transformers import SentenceTransformer
        # model = SentenceTransformer(self.embedding_model)
        # texts = [doc['content'] for doc in corpus]
        # embeddings = model.encode(texts, show_progress_bar=True)
        # return embeddings

        raise NotImplementedError(
            "Replace with your embedding model. "
            "See docs/REPRODUCIBILITY.md for embedding setup."
        )

    def _get_expected_performance(self, threshold: float, uniformity: float) -> Dict:
        """
        Get expected performance metrics based on paper results and corpus properties.

        Corpus uniformity interpretation:
            < 0.3: Highly uniform (like FEVER) - semantic drift works moderately
            0.3-0.5: Mixed uniformity - reduced effectiveness
            > 0.5: Highly diverse (like Security SE) - poor discrimination
        """
        if uniformity < 0.3:
            # Uniform corpus (FEVER-like)
            return {
                'corpus_type': 'General Knowledge (Uniform)',
                'expected_tpr': 0.500,
                'expected_fpr': 0.004,
                'expected_precision': 0.231,
                'expected_f1': 0.226,
                'note': 'Moderate performance on uniform semantic spaces',
                'recommendation': 'Use as supplementary detection, not primary method'
            }
        elif uniformity < 0.5:
            # Mixed corpus
            return {
                'corpus_type': 'Mixed Semantic Diversity',
                'expected_tpr': 0.200,
                'expected_fpr': 0.010,
                'expected_precision': 0.100,
                'expected_f1': 0.120,
                'note': 'Reduced effectiveness on mixed corpora',
                'recommendation': 'Not recommended - use Query Pattern Differential instead'
            }
        else:
            # Diverse corpus (Security SE-like)
            return {
                'corpus_type': 'Technical/Specialized (Diverse)',
                'expected_tpr': 0.167,
                'expected_fpr': 0.001,
                'expected_precision': 0.043,
                'expected_f1': 0.069,
                'note': 'Poor discrimination on diverse technical corpora',
                'recommendation': 'NOT RECOMMENDED - technical documents naturally occupy diverse embedding space'
            }

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

    def visualize_embedding_space(
        self,
        results: List[SemanticDriftResult],
        save_path: Optional[str] = None
    ):
        """
        Visualize document positions in 2D PCA space.

        Args:
            results: List of SemanticDriftResult from analyze_corpus()
            save_path: Optional path to save figure

        Note: Requires matplotlib. Install with: pip install matplotlib
        """
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            raise ImportError("Visualization requires matplotlib: pip install matplotlib")

        # Extract PCA positions (use first 2 components)
        positions = np.array([r.pca_position[:2] for r in results])
        flagged = np.array([r.is_flagged for r in results])

        # Plot
        plt.figure(figsize=(10, 8))
        plt.scatter(
            positions[~flagged, 0],
            positions[~flagged, 1],
            c='blue',
            alpha=0.5,
            label='Benign (predicted)',
            s=30
        )
        plt.scatter(
            positions[flagged, 0],
            positions[flagged, 1],
            c='red',
            alpha=0.7,
            label='Flagged (suspicious)',
            s=50,
            marker='X'
        )

        plt.xlabel('PCA Component 1')
        plt.ylabel('PCA Component 2')
        plt.title('Document Embedding Space (Semantic Drift Detection)')
        plt.legend()
        plt.grid(True, alpha=0.3)

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        else:
            plt.show()


def example_usage():
    """
    Example usage of Semantic Drift Detector.

    This shows the API - actual implementation requires:
    1. Real corpus data
    2. Embedding model setup
    3. Threshold calibration for your corpus
    """

    # Step 1: Initialize detector
    detector = SemanticDriftDetector(
        embedding_model="sentence-transformers/all-MiniLM-L6-v2",
        n_neighbors=20,
        contamination=0.01  # Expect 1% outliers
    )

    # Step 2: Prepare corpus
    corpus = [
        {'id': 'doc1', 'content': 'Legitimate security content...'},
        {'id': 'doc2', 'content': 'Normal database documentation...'},
        # ... more documents
    ]

    # Step 3: Analyze corpus
    try:
        threshold = detector.recommend_threshold('technical')  # or 'general'
        results = detector.analyze_corpus(corpus, threshold=threshold)

        print(f"Flagged {results['total_flagged']} / {results['total_documents']} documents")
        print(f"Corpus uniformity: {results['corpus_uniformity']:.3f}")
        print(f"Expected FPR: {results['expected_performance']['expected_fpr']:.4f}")
        print(f"Recommendation: {results['expected_performance']['recommendation']}")

        # Review flagged documents
        for doc in results['flagged_documents']:
            print(f"Document {doc.document_id}:")
            print(f"  Distance to centroid: {doc.distance_to_centroid:.3f}")
            print(f"  LOF score: {doc.lof_score:.3f}")

        # Optional: Visualize
        # detector.visualize_embedding_space(results['all_scores'], 'embedding_space.png')

    except NotImplementedError:
        print("Note: Requires embedding model implementation")
        print("See docs/REPRODUCIBILITY.md for setup instructions")


if __name__ == "__main__":
    example_usage()
