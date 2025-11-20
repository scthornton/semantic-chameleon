"""
Keyword Anomaly Detection

This method detects poisoned documents by identifying statistically rare
keywords that are anomalous for the corpus domain. Attack documents often
contain attack-related terms that stand out in general knowledge corpora.

Paper: "Corpus-Dependent RAG Poisoning"
Method: Keyword Anomaly (Section 4.3, Method 2)
Performance: Corpus-dependent (0.556 F1 FEVER, 0.000 Security SE)

DEFENSIVE USE ONLY - No attack implementations included.
"""

import numpy as np
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from collections import Counter
import re


@dataclass
class KeywordAnomalyResult:
    """Result from keyword anomaly analysis"""
    document_id: str
    anomalous_keywords: List[Tuple[str, float]]  # (keyword, IDF score)
    max_idf_score: float
    mean_idf_score: float
    anomaly_keyword_count: int
    is_flagged: bool
    threshold_used: float


class KeywordAnomalyDetector:
    """
    Detects poisoned documents using IDF-based keyword anomaly detection.

    Key Insight: Attack documents often contain domain-specific attack keywords
    (e.g., "bypass", "exfiltrate", "inject") that are statistically rare in
    general knowledge corpora. High IDF scores for attack-related terms signal
    potential poisoning.

    Algorithm (Paper Section 4.3):
    1. Compute IDF scores for all terms in corpus
    2. Define attack-related keyword list (domain-specific)
    3. For each document, identify keywords with high IDF scores
    4. Flag documents with anomalously high keyword counts or IDF scores

    Corpus Dependency (Critical - Paper Section 7.1):
    - FEVER (general knowledge): Attack keywords are RARE → F1 = 0.556
    - Security SE (technical): Attack keywords are COMMON → F1 = 0.000
    - This method is INEFFECTIVE on technical/security corpora
    - Only use on general knowledge bases (Wikipedia, news, encyclopedias)

    Why Technical Corpora Fail:
    Terms like "authentication", "bypass", "vulnerability" appear naturally
    in security documentation, creating high false positive rates and making
    attack documents indistinguishable from benign technical content.

    Usage:
        detector = KeywordAnomalyDetector(attack_keywords=your_keyword_list)
        results = detector.analyze_corpus(corpus, threshold=10.0)
    """

    def __init__(
        self,
        attack_keywords: Optional[List[str]] = None,
        idf_threshold: float = 5.0,
        min_anomalous_count: int = 3
    ):
        """
        Initialize Keyword Anomaly Detector.

        Args:
            attack_keywords: List of attack-related keywords (domain-specific)
                            If None, uses default general attack vocabulary
            idf_threshold: Minimum IDF score to consider keyword anomalous
            min_anomalous_count: Minimum number of anomalous keywords to flag

        Note: Quality of detection depends on keyword list relevance to:
              1. Your threat model (what attacks are you defending against?)
              2. Your corpus domain (what's "normal" in your content?)
        """
        if attack_keywords is None:
            # Default attack keyword vocabulary (SANITIZED examples)
            # In production, customize for YOUR threats and domain
            self.attack_keywords = self._get_default_keywords()
        else:
            self.attack_keywords = [kw.lower() for kw in attack_keywords]

        self.idf_threshold = idf_threshold
        self.min_anomalous_count = min_anomalous_count

        # Validated thresholds from paper (Section 6.2.2)
        self.recommended_thresholds = {
            'security_se': None,  # NOT RECOMMENDED - 0% detection rate
            'fever': 10.0,        # 83.3% TPR, 0.002% FPR, 41.7% Precision
            'general': 10.0       # Default for general knowledge corpora
        }

    def analyze_corpus(
        self,
        corpus: List[Dict],
        threshold: float = 10.0,
        return_all_scores: bool = False
    ) -> Dict:
        """
        Analyze entire corpus for poisoned documents using keyword anomaly.

        Args:
            corpus: List of documents with 'id' and 'content' fields
            threshold: IDF score threshold for flagging keywords
            return_all_scores: If True, return scores for all documents

        Returns:
            Dictionary with detection results:
                - flagged_documents: List of KeywordAnomalyResult for flagged docs
                - total_flagged: Count of flagged documents
                - corpus_idf_stats: Statistics about IDF distribution
                - keyword_occurrence_rate: How often attack keywords appear
                - expected_performance: Expected TPR/FPR based on corpus type
                - all_scores: (Optional) Scores for all documents
        """
        # Step 1: Compute IDF scores for entire corpus
        idf_scores = self._compute_idf_scores(corpus)

        # Step 2: Analyze keyword occurrence patterns
        keyword_occurrence_rate = self._compute_keyword_occurrence_rate(corpus)

        # Step 3: Assess corpus suitability for this method
        corpus_type = self._assess_corpus_suitability(keyword_occurrence_rate)

        # Step 4: Analyze each document
        results = []
        for doc in corpus:
            # Tokenize document
            tokens = self._tokenize(doc['content'])

            # Find anomalous keywords
            anomalous = []
            for keyword in self.attack_keywords:
                if keyword in tokens:
                    idf = idf_scores.get(keyword, 0.0)
                    if idf >= threshold:
                        anomalous.append((keyword, idf))

            # Sort by IDF score (descending)
            anomalous.sort(key=lambda x: x[1], reverse=True)

            # Compute aggregate scores
            max_idf = anomalous[0][1] if anomalous else 0.0
            mean_idf = np.mean([score for _, score in anomalous]) if anomalous else 0.0

            # Flagging criteria
            is_flagged = len(anomalous) >= self.min_anomalous_count

            result = KeywordAnomalyResult(
                document_id=doc['id'],
                anomalous_keywords=anomalous,
                max_idf_score=float(max_idf),
                mean_idf_score=float(mean_idf),
                anomaly_keyword_count=len(anomalous),
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
            'keyword_occurrence_rate': keyword_occurrence_rate,
            'corpus_suitability': corpus_type,
            'expected_performance': self._get_expected_performance(corpus_type)
        }

        if return_all_scores:
            output['all_scores'] = results

        return output

    def _compute_idf_scores(self, corpus: List[Dict]) -> Dict[str, float]:
        """
        Compute Inverse Document Frequency (IDF) for all terms.

        Formula: IDF(term) = log(N / df(term))
        Where:
            N = total number of documents
            df(term) = number of documents containing term
        """
        N = len(corpus)
        doc_frequencies = Counter()

        # Count document frequencies
        for doc in corpus:
            tokens = set(self._tokenize(doc['content']))
            for token in tokens:
                doc_frequencies[token] += 1

        # Compute IDF scores
        idf_scores = {}
        for term, df in doc_frequencies.items():
            idf_scores[term] = np.log(N / df)

        return idf_scores

    def _compute_keyword_occurrence_rate(self, corpus: List[Dict]) -> float:
        """
        Compute what percentage of documents contain attack keywords.

        High occurrence rate (>10%) suggests technical corpus where this
        method will fail. Low rate (<5%) suggests general corpus where
        method may work.
        """
        docs_with_keywords = 0

        for doc in corpus:
            tokens = set(self._tokenize(doc['content']))
            if any(keyword in tokens for keyword in self.attack_keywords):
                docs_with_keywords += 1

        return docs_with_keywords / len(corpus) if corpus else 0

    def _assess_corpus_suitability(self, occurrence_rate: float) -> str:
        """
        Assess whether corpus is suitable for keyword anomaly detection.

        Thresholds:
            < 5%: General knowledge corpus - RECOMMENDED
            5-15%: Mixed corpus - LIMITED EFFECTIVENESS
            > 15%: Technical corpus - NOT RECOMMENDED
        """
        if occurrence_rate < 0.05:
            return 'general_knowledge'
        elif occurrence_rate < 0.15:
            return 'mixed'
        else:
            return 'technical'

    def _tokenize(self, text: str) -> Set[str]:
        """
        Tokenize text into lowercase word set.

        In production, use proper tokenizer:
        - spaCy for linguistic features
        - nltk for stemming/lemmatization
        - Your embedding model's tokenizer for consistency
        """
        # Simple tokenization: lowercase + alphanumeric only
        tokens = re.findall(r'\b\w+\b', text.lower())
        return set(tokens)

    def _get_default_keywords(self) -> List[str]:
        """
        Get default attack keyword vocabulary.

        IMPORTANT: These are SANITIZED educational examples. In production:
        1. Customize for YOUR threat model
        2. Consider YOUR corpus domain
        3. Test on representative data
        4. Update as attack patterns evolve

        Categories included:
        - Authentication/authorization attacks
        - Data exfiltration
        - Injection attacks
        - System exploitation
        - Cryptographic attacks
        """
        return [
            # SANITIZED - General security terminology
            'bypass', 'authentication', 'vulnerability', 'exploit',
            'injection', 'exfiltrate', 'exfiltration', 'payload',
            'backdoor', 'privilege', 'escalation', 'unauthorized',
            'malicious', 'adversarial', 'compromise', 'breach',
            'penetration', 'intrusion', 'hijacking', 'spoofing',
            'phishing', 'malware', 'ransomware', 'trojan',
            'keylogger', 'rootkit', 'shellcode', 'buffer overflow',
            'sql injection', 'xss', 'csrf', 'session hijacking'
        ]

    def _get_expected_performance(self, corpus_type: str) -> Dict:
        """
        Get expected performance metrics based on corpus type.
        """
        if corpus_type == 'general_knowledge':
            return {
                'corpus_type': 'General Knowledge (e.g., FEVER, Wikipedia)',
                'expected_tpr': 0.833,
                'expected_fpr': 0.002,
                'expected_precision': 0.417,
                'expected_f1': 0.556,
                'note': 'Good performance - attack keywords are statistically rare',
                'recommendation': 'RECOMMENDED for general knowledge corpora'
            }
        elif corpus_type == 'mixed':
            return {
                'corpus_type': 'Mixed Semantic Domain',
                'expected_tpr': 0.300,
                'expected_fpr': 0.050,
                'expected_precision': 0.100,
                'expected_f1': 0.150,
                'note': 'Reduced effectiveness - attack keywords partially normalized',
                'recommendation': 'Use with caution, consider Query Pattern Differential instead'
            }
        else:  # technical
            return {
                'corpus_type': 'Technical/Security (e.g., Security SE, code repos)',
                'expected_tpr': 0.000,
                'expected_fpr': 0.100,
                'expected_precision': 0.000,
                'expected_f1': 0.000,
                'note': 'FAILS completely - attack keywords are common in technical content',
                'recommendation': 'NOT RECOMMENDED - use Query Pattern Differential instead'
            }

    def recommend_threshold(self, corpus_type: str) -> Optional[float]:
        """
        Recommend threshold based on corpus type.

        Args:
            corpus_type: 'technical' or 'general'

        Returns:
            Recommended threshold value, or None if method not recommended
        """
        if corpus_type.lower() in ['technical', 'security_se', 'code', 'api']:
            return None  # Not recommended
        else:
            return self.recommended_thresholds['fever']

    def add_custom_keywords(self, keywords: List[str]):
        """
        Add custom attack keywords to detection vocabulary.

        Args:
            keywords: List of domain-specific attack terms

        Example:
            detector.add_custom_keywords(['prompt injection', 'jailbreak', 'DAN'])
        """
        self.attack_keywords.extend([kw.lower() for kw in keywords])
        # Remove duplicates
        self.attack_keywords = list(set(self.attack_keywords))


def example_usage():
    """
    Example usage of Keyword Anomaly Detector.

    This shows the API and demonstrates corpus suitability assessment.
    """

    # Step 1: Initialize detector
    detector = KeywordAnomalyDetector(
        idf_threshold=10.0,
        min_anomalous_count=3
    )

    # Optional: Add domain-specific keywords
    detector.add_custom_keywords([
        'prompt injection',
        'jailbreak',
        'adversarial example'
    ])

    # Step 2: Prepare corpus
    corpus = [
        {'id': 'doc1', 'content': 'The history of cryptography dates back to ancient times...'},
        {'id': 'doc2', 'content': 'Machine learning models are trained on large datasets...'},
        # ... more documents
    ]

    # Step 3: Analyze corpus
    threshold = detector.recommend_threshold('general')

    if threshold is None:
        print("WARNING: Keyword Anomaly Detection not recommended for technical corpora")
        print("Use Query Pattern Differential instead")
    else:
        results = detector.analyze_corpus(corpus, threshold=threshold)

        print(f"Corpus suitability: {results['corpus_suitability']}")
        print(f"Keyword occurrence rate: {results['keyword_occurrence_rate']:.1%}")
        print(f"Flagged {results['total_flagged']} / {results['total_documents']} documents")
        print(f"Expected FPR: {results['expected_performance']['expected_fpr']:.4f}")
        print(f"Recommendation: {results['expected_performance']['recommendation']}")

        # Review flagged documents
        for doc in results['flagged_documents']:
            print(f"\nDocument {doc.document_id}:")
            print(f"  Anomalous keyword count: {doc.anomaly_keyword_count}")
            print(f"  Max IDF score: {doc.max_idf_score:.2f}")
            print(f"  Keywords: {[kw for kw, _ in doc.anomalous_keywords[:5]]}")


if __name__ == "__main__":
    example_usage()
