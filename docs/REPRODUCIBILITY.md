# Reproducibility Guide

This guide provides step-by-step instructions for reproducing the results reported in the paper "Corpus-Dependent RAG Poisoning: Characterizing the Attack-Defense Trade-off in Retrieval-Augmented Generation Systems."

**Goal**: Enable independent verification of our findings using publicly available datasets and open-source tools.

**Time Required**: 8-16 hours (mostly compute time)

**Compute Requirements**: 8 vCPU, 32GB RAM, 100GB storage (e.g., GCP n1-standard-8 or AWS c5.2xlarge)

---

## Table of Contents

1. [Overview](#overview)
2. [Environment Setup](#environment-setup)
3. [Dataset Preparation](#dataset-preparation)
4. [Detection Evaluation](#detection-evaluation)
5. [Defense Evaluation](#defense-evaluation)
6. [Statistical Analysis](#statistical-analysis)
7. [Figure Generation](#figure-generation)
8. [Expected Results](#expected-results)
9. [Troubleshooting](#troubleshooting)

---

## Overview

### What Can Be Reproduced

✅ **Detection Method Performance** (Section 6.2):
- Query Pattern Differential: F1 scores on FEVER and Security SE
- Keyword Anomaly: F1 scores on FEVER (Security SE: 0.000 as expected)
- Semantic Drift: F1 scores on both corpora
- ROC curves, precision/recall trade-offs

✅ **Corpus Analysis** (Section 7.1):
- IDF distributions
- Semantic diversity metrics
- Attack keyword occurrence rates
- Statistical comparisons between corpora

✅ **Statistical Tests** (Section 6.3):
- Chi-square tests for method comparisons
- Effect size measurements (Cohen's h)
- Confidence intervals (Wilson score method)

### What Cannot Be Reproduced

❌ **Attack Success Rates** (Section 6.1):
- Requires gradient-optimized attack documents (not included for safety)
- Paper reports: 38.0% success pure vector, 0% success hybrid retrieval
- Researchers can verify defense architecture without attacking

❌ **Attack Document Generation**:
- GCG optimization code not included (safety)
- Dual-document generation not included (safety)

**Rationale**: This repository prioritizes defensive research. Attack implementations are omitted to prevent weaponization while still enabling defense validation.

---

## Environment Setup

### Step 1: Install Dependencies

```bash
# Clone repository
git clone https://github.com/yourusername/corpus-dependent-rag-poisoning
cd corpus-dependent-rag-poisoning

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### Step 2: Configure Embedding Model

**Option A: Local Embeddings** (Recommended)

```python
# Using sentence-transformers (no API key needed)
from sentence_transformers import SentenceTransformer

model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')

# Test embedding
test_embedding = model.encode("Hello world")
print(f"Embedding dimension: {len(test_embedding)}")  # Should be 384
```

**Option B: OpenAI Embeddings** (Requires API key)

```python
# Set API key
export OPENAI_API_KEY='your-key-here'

# Using OpenAI API
import openai

response = openai.embeddings.create(
    model="text-embedding-3-small",
    input="Hello world"
)

embedding = response.data[0].embedding
print(f"Embedding dimension: {len(embedding)}")  # Should be 1536
```

**Paper Configuration**: We used OpenAI `text-embedding-ada-002` (1536 dimensions). Results should be similar with other embedding models, though exact numbers may vary.

### Step 3: Verify Installation

```bash
# Run test suite
pytest tests/

# Expected output:
# ✓ test_embedding_model_loads
# ✓ test_hybrid_retrieval_initialization
# ✓ test_detection_methods_import
# ✓ test_evaluation_metrics
```

---

## Dataset Preparation

### Dataset 1: FEVER (Fact Extraction and VERification)

**Source**: https://fever.ai/dataset/fever.html

**License**: Creative Commons Attribution-ShareAlike 4.0

**Size**: ~185k Wikipedia claims

**Download**:

```bash
# Download FEVER dataset
mkdir -p data/fever
cd data/fever

wget https://fever.ai/download/fever/train.jsonl
wget https://fever.ai/download/fever/dev.jsonl

# Combine train + dev
cat train.jsonl dev.jsonl > fever_combined.jsonl
```

**Preprocessing**:

```python
import json

def preprocess_fever(input_file, output_file, max_docs=10000):
    """
    Convert FEVER format to our corpus format.

    FEVER format:
        {"id": 123, "claim": "...", "evidence": [[doc_id, sent_id, text, label]], ...}

    Our format:
        {"id": "fever_123", "content": "...", "source": "FEVER"}
    """
    corpus = []
    seen_ids = set()

    with open(input_file, 'r') as f:
        for line in f:
            if len(corpus) >= max_docs:
                break

            entry = json.loads(line)

            # Use claim as document content
            doc_id = f"fever_{entry['id']}"

            if doc_id not in seen_ids:
                corpus.append({
                    'id': doc_id,
                    'content': entry['claim'],
                    'source': 'FEVER'
                })
                seen_ids.add(doc_id)

    # Save corpus
    with open(output_file, 'w') as f:
        json.dump(corpus, f, indent=2)

    print(f"Preprocessed {len(corpus)} documents")
    return corpus

# Run preprocessing
preprocess_fever('data/fever/fever_combined.jsonl', 'data/fever/corpus.json')
```

### Dataset 2: Security Stack Exchange

**Source**: https://archive.org/details/stackexchange

**License**: Creative Commons Attribution-ShareAlike 4.0

**Size**: ~30k questions + answers

**Download**:

```bash
# Download Security Stack Exchange dump
mkdir -p data/security_se
cd data/security_se

# Download from Internet Archive (warning: ~800MB compressed)
wget https://archive.org/download/stackexchange/security.stackexchange.com.7z

# Extract (requires 7z)
7z x security.stackexchange.com.7z
```

**Preprocessing**:

```python
import xml.etree.ElementTree as ET
import json

def preprocess_security_se(posts_xml, output_file, max_docs=10000):
    """
    Convert Stack Exchange XML to our corpus format.

    XML format:
        <row Id="123" PostTypeId="1" Title="..." Body="..." Tags="..." />

    Our format:
        {"id": "se_123", "content": "Title + Body", "source": "Security SE"}
    """
    tree = ET.parse(posts_xml)
    root = tree.getroot()

    corpus = []

    for post in root.findall('row'):
        if len(corpus) >= max_docs:
            break

        # Only include questions (PostTypeId=1) and answers (PostTypeId=2)
        post_type = post.get('PostTypeId')
        if post_type not in ['1', '2']:
            continue

        post_id = post.get('Id')
        title = post.get('Title', '')
        body = post.get('Body', '')

        # Combine title and body
        content = f"{title}\n\n{body}" if title else body

        # Remove HTML tags (simple approach)
        import re
        content = re.sub(r'<[^>]+>', '', content)

        corpus.append({
            'id': f'se_{post_id}',
            'content': content.strip(),
            'source': 'Security SE'
        })

    # Save corpus
    with open(output_file, 'w') as f:
        json.dump(corpus, f, indent=2)

    print(f"Preprocessed {len(corpus)} documents")
    return corpus

# Run preprocessing
preprocess_security_se(
    'data/security_se/Posts.xml',
    'data/security_se/corpus.json'
)
```

### Validation

```python
import json

# Load both corpora
with open('data/fever/corpus.json') as f:
    fever_corpus = json.load(f)

with open('data/security_se/corpus.json') as f:
    security_se_corpus = json.load(f)

print(f"FEVER corpus: {len(fever_corpus)} documents")
print(f"Security SE corpus: {len(security_se_corpus)} documents")

# Sample documents
print(f"\nFEVER example: {fever_corpus[0]['content'][:100]}...")
print(f"Security SE example: {security_se_corpus[0]['content'][:100]}...")
```

**Expected Output**:
```
FEVER corpus: 10000 documents
Security SE corpus: 10000 documents

FEVER example: The Great Wall of China is visible from space with the naked eye...
Security SE example: What are the best practices for implementing multi-factor authentication...
```

---

## Detection Evaluation

### Step 1: Generate Query Sets

```python
from detection.query_pattern import QueryPatternDetector
import random

# Benign queries: Sample from corpus
def generate_benign_queries(corpus, num_queries=100):
    """Sample titles/questions from corpus as benign queries"""
    # For FEVER: Use claims directly
    # For Security SE: Use question titles
    samples = random.sample(corpus, min(num_queries, len(corpus)))
    return [doc['content'][:200] for doc in samples]  # Truncate long content

# Sensitive queries: Craft attack-related queries
sensitive_queries = [
    # Authentication attacks (sanitized examples)
    "bypass authentication systems",
    "circumvent access controls",
    "unauthorized system access",

    # Data exfiltration (sanitized)
    "extract sensitive database information",
    "access confidential data",
    "retrieve private records",

    # Add 15-20 more relevant to your evaluation
    # See examples/sanitized_scenarios.json for templates
]

# Generate for both corpora
fever_benign = generate_benign_queries(fever_corpus, 100)
se_benign = generate_benign_queries(security_se_corpus, 100)
```

### Step 2: Compute Embeddings

```python
from sentence_transformers import SentenceTransformer
import numpy as np
import pickle

model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')

def embed_corpus(corpus, model, output_file):
    """Compute and cache embeddings for entire corpus"""
    print(f"Computing embeddings for {len(corpus)} documents...")

    # Extract text
    texts = [doc['content'] for doc in corpus]

    # Compute embeddings in batches
    embeddings = model.encode(
        texts,
        batch_size=64,
        show_progress_bar=True,
        normalize_embeddings=True  # For cosine similarity
    )

    # Save embeddings
    with open(output_file, 'wb') as f:
        pickle.dump({
            'embeddings': embeddings,
            'doc_ids': [doc['id'] for doc in corpus]
        }, f)

    print(f"Saved embeddings to {output_file}")
    return embeddings

# Compute embeddings for both corpora
fever_embeddings = embed_corpus(fever_corpus, model, 'data/fever/embeddings.pkl')
se_embeddings = embed_corpus(security_se_corpus, model, 'data/security_se/embeddings.pkl')
```

### Step 3: Inject Synthetic Attack Documents

For reproducibility, we create synthetic "attack" documents that mimic the properties of poisoned content without being actually weaponizable:

```python
def create_synthetic_attacks(corpus, num_attacks=50):
    """
    Create synthetic attack documents for evaluation.

    These are benign documents with HIGH sensitive query similarity
    and LOW benign query similarity (mimicking attack pattern).

    NOT actual attacks - just evaluation proxies.
    """
    synthetic_attacks = []

    for i in range(num_attacks):
        # Create document with attack-related keywords but benign content
        doc = {
            'id': f'synthetic_attack_{i}',
            'content': f"Security research document {i} about authentication and access control best practices for preventing unauthorized access.",
            'source': 'SYNTHETIC',
            'label': 'malicious'  # Ground truth for evaluation
        }
        synthetic_attacks.append(doc)

    return synthetic_attacks

# Add synthetic attacks to corpus
fever_attacks = create_synthetic_attacks(fever_corpus, 50)
se_attacks = create_synthetic_attacks(security_se_corpus, 50)

fever_corpus_eval = fever_corpus + fever_attacks
se_corpus_eval = security_se_corpus + se_attacks
```

### Step 4: Run Detection Methods

```python
from detection.query_pattern import QueryPatternDetector
from detection.keyword_anomaly import KeywordAnomalyDetector
from detection.semantic_drift import SemanticDriftDetector
from evaluation.metrics import DetectionEvaluator

# Initialize detectors
query_detector = QueryPatternDetector(
    benign_queries=fever_benign,
    sensitive_queries=sensitive_queries
)

keyword_detector = KeywordAnomalyDetector()
semantic_detector = SemanticDriftDetector()

# Run detection on FEVER
print("Evaluating on FEVER corpus...")

query_results_fever = query_detector.analyze_corpus(
    fever_corpus_eval,
    threshold=0.15  # Paper threshold for FEVER
)

keyword_results_fever = keyword_detector.analyze_corpus(
    fever_corpus_eval,
    threshold=10.0  # Paper threshold
)

semantic_results_fever = semantic_detector.analyze_corpus(
    fever_corpus_eval,
    threshold=2.0
)

# Repeat for Security SE
print("\nEvaluating on Security SE corpus...")

query_detector_se = QueryPatternDetector(
    benign_queries=se_benign,
    sensitive_queries=sensitive_queries
)

query_results_se = query_detector_se.analyze_corpus(
    se_corpus_eval,
    threshold=0.20  # Paper threshold for Security SE
)

# ... etc for other methods
```

### Step 5: Compute Metrics

```python
from evaluation.metrics import DetectionEvaluator

evaluator = DetectionEvaluator()

# Ground truth: last 50 documents are synthetic attacks
ground_truth = [False] * len(fever_corpus) + [True] * 50

# Predictions from detection methods
query_predictions = [
    doc.document_id in [r.document_id for r in query_results_fever['flagged_documents']]
    for doc in fever_corpus_eval
]

# Evaluate
query_metrics = evaluator.evaluate(query_predictions, ground_truth)

print(f"Query Pattern Differential (FEVER):")
print(f"  TPR: {query_metrics.tpr:.3f} [{query_metrics.tpr_ci[0]:.3f}, {query_metrics.tpr_ci[1]:.3f}]")
print(f"  FPR: {query_metrics.fpr:.4f} [{query_metrics.fpr_ci[0]:.4f}, {query_metrics.fpr_ci[1]:.4f}]")
print(f"  Precision: {query_metrics.precision:.3f}")
print(f"  F1: {query_metrics.f1_score:.3f}")

# Compare to paper results:
# Paper: TPR=0.667, FPR=0.0001, Precision=0.600, F1=0.632
```

---

## Defense Evaluation

### Step 1: Implement Pure Vector Baseline

```python
def pure_vector_retrieval(query, corpus, embeddings, k=10):
    """Baseline: Pure vector similarity (vulnerable)"""
    query_embedding = model.encode(query, normalize_embeddings=True)
    similarities = np.dot(embeddings, query_embedding)
    top_k_indices = np.argsort(similarities)[-k:][::-1]
    return [corpus[i]['id'] for i in top_k_indices]
```

### Step 2: Implement Hybrid Retrieval

```python
from defense.hybrid_retrieval import HybridRetriever

retriever = HybridRetriever(alpha=0.5)

def hybrid_retrieval(query, corpus, k=10):
    """Defense: Hybrid BM25+vector"""
    return retriever.retrieve(query, corpus, k)
```

### Step 3: Evaluate Co-Retrieval Rates

```python
def evaluate_co_retrieval(retrieval_fn, queries, corpus, attack_doc_ids):
    """
    Measure how often attack documents are retrieved.

    Co-retrieval rate: Percentage of queries where ≥1 attack doc in top-k
    """
    co_retrievals = 0

    for query in queries:
        results = retrieval_fn(query, corpus, k=10)
        result_ids = [r['id'] for r in results]

        # Check if any attack doc retrieved
        if any(doc_id in attack_doc_ids for doc_id in result_ids):
            co_retrievals += 1

    co_retrieval_rate = co_retrievals / len(queries)
    return co_retrieval_rate

# Evaluate pure vector (baseline)
attack_ids = [doc['id'] for doc in fever_attacks]
pure_vector_rate = evaluate_co_retrieval(
    pure_vector_retrieval,
    sensitive_queries,
    fever_corpus_eval,
    attack_ids
)

# Evaluate hybrid retrieval
hybrid_rate = evaluate_co_retrieval(
    hybrid_retrieval,
    sensitive_queries,
    fever_corpus_eval,
    attack_ids
)

print(f"Co-Retrieval Rates:")
print(f"  Pure Vector: {pure_vector_rate:.1%}")
print(f"  Hybrid (α=0.5): {hybrid_rate:.1%}")

# Paper results: Pure Vector ~38%, Hybrid 0%
```

---

## Statistical Analysis

### Confidence Intervals

```python
from evaluation.metrics import DetectionEvaluator

evaluator = DetectionEvaluator(confidence_level=0.95)

# Compute Wilson score intervals for co-retrieval rate
n_trials = len(sensitive_queries)
n_successes = int(pure_vector_rate * n_trials)

ci_lower, ci_upper = evaluator._wilson_score_interval(n_successes, n_trials)

print(f"Pure Vector Co-Retrieval: {pure_vector_rate:.1%}")
print(f"  95% CI: [{ci_lower:.1%}, {ci_upper:.1%}]")

# Paper: 38.0% [95% CI: 25.9%, 51.8%]
```

### Method Comparison

```python
# Compare detection methods statistically
method_results = {
    'Query Pattern': query_metrics,
    'Keyword Anomaly': keyword_metrics,
    'Semantic Drift': semantic_metrics
}

comparison = evaluator.compare_methods(method_results)

print("\nMethod Ranking (by F1 score):")
for rank, (method, f1) in enumerate(comparison['ranking'], 1):
    print(f"  {rank}. {method}: {f1:.3f}")

print("\nPairwise Comparisons:")
for pair, stats in comparison['pairwise_comparisons'].items():
    print(f"  {pair}:")
    print(f"    p-value: {stats['p_value']:.4f}")
    print(f"    Significant: {stats['significant']}")
    print(f"    Effect size: {stats['effect_size']:.3f} ({stats['interpretation']})")
```

---

## Figure Generation

### ROC Curves

```python
import matplotlib.pyplot as plt

def plot_roc_curves(roc_data, corpus_name, output_file):
    """Generate ROC curve figure (Paper Figure 2)"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Plot 1: ROC Curve (TPR vs FPR)
    for method_name, roc_curve in roc_data.items():
        fprs = [p.fpr for p in roc_curve]
        tprs = [p.tpr for p in roc_curve]
        ax1.plot(fprs, tprs, label=method_name, linewidth=2)

    ax1.plot([0, 1], [0, 1], 'k--', label='Random', linewidth=1)
    ax1.set_xlabel('False Positive Rate')
    ax1.set_ylabel('True Positive Rate')
    ax1.set_title(f'ROC Curve ({corpus_name})')
    ax1.legend()
    ax1.grid(True, alpha=0.3)

    # Plot 2: Precision-Recall Curve
    for method_name, roc_curve in roc_data.items():
        recalls = [p.tpr for p in roc_curve]
        precisions = [p.precision for p in roc_curve]
        ax2.plot(recalls, precisions, label=method_name, linewidth=2)

    ax2.set_xlabel('Recall (TPR)')
    ax2.set_ylabel('Precision')
    ax2.set_title(f'Precision-Recall Curve ({corpus_name})')
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Saved figure to {output_file}")

# Generate ROC curves for both corpora
roc_data_fever = {
    'Query Pattern': evaluator.compute_roc_curve(query_scores_fever, ground_truth),
    'Keyword Anomaly': evaluator.compute_roc_curve(keyword_scores_fever, ground_truth),
    'Semantic Drift': evaluator.compute_roc_curve(semantic_scores_fever, ground_truth)
}

plot_roc_curves(roc_data_fever, 'FEVER', 'figures/roc_fever.png')
```

### Performance Comparison Tables

```python
import pandas as pd

def generate_results_table(results_dict, corpus_name):
    """Generate performance table (Paper Table 2, Table 3)"""
    rows = []

    for method_name, metrics in results_dict.items():
        rows.append({
            'Method': method_name,
            'TPR': f"{metrics.tpr:.3f}",
            'FPR': f"{metrics.fpr:.4f}",
            'Precision': f"{metrics.precision:.3f}",
            'F1': f"{metrics.f1_score:.3f}"
        })

    df = pd.DataFrame(rows)
    print(f"\n{corpus_name} Results:")
    print(df.to_string(index=False))

    # Save to CSV
    df.to_csv(f'results/{corpus_name.lower()}_results.csv', index=False)

# Generate tables
generate_results_table({
    'Query Pattern': query_metrics_fever,
    'Keyword Anomaly': keyword_metrics_fever,
    'Semantic Drift': semantic_metrics_fever
}, 'FEVER')
```

---

## Expected Results

### Detection Performance (Section 6.2)

**FEVER Corpus**:
| Method | TPR | FPR | Precision | F1 |
|--------|-----|-----|-----------|-----|
| Query Pattern | 0.667 | 0.0001 | 0.600 | 0.632 |
| Keyword Anomaly | 0.833 | 0.002 | 0.417 | 0.556 |
| Semantic Drift | 0.500 | 0.004 | 0.231 | 0.226 |

**Security SE Corpus**:
| Method | TPR | FPR | Precision | F1 |
|--------|-----|-----|-----------|-----|
| Query Pattern | 0.167 | 0.0002 | 0.176 | 0.171 |
| Keyword Anomaly | 0.000 | 0.100 | 0.000 | 0.000 |
| Semantic Drift | 0.167 | 0.001 | 0.043 | 0.069 |

**Key Findings**:
- Query Pattern Differential is best method across both corpora
- Technical corpora (Security SE) show 13-62× worse performance
- Keyword Anomaly fails completely on technical content

### Defense Effectiveness (Section 6.1)

**Co-Retrieval Rates**:
| α (vector weight) | FEVER | Security SE |
|-------------------|-------|-------------|
| 1.0 (pure vector) | 38.0% | ~40% |
| 0.7 | 0% | 0% |
| 0.5 | 0% | 0% |
| 0.3 | 0% | 0% |

**Key Finding**: Hybrid retrieval with α ≤ 0.7 achieves 0% co-retrieval across all 50 gradient-optimized attacks (paper result)

### Variance Expectations

Your results may vary slightly due to:
- Different embedding models (we used OpenAI, you might use sentence-transformers)
- Random sampling of benign queries
- Different corpus subsets
- Synthetic attacks vs real gradient-optimized attacks

**Acceptable variance**: ±0.05 for F1 scores, ±0.02 for TPR/FPR

---

## Troubleshooting

### Common Issues

**Issue 1: Embeddings fail with OOM**
```python
# Solution: Use smaller batches
embeddings = model.encode(texts, batch_size=16)  # Reduce from 64
```

**Issue 2: Detection methods run slowly**
```python
# Solution: Use smaller corpus subset for testing
test_corpus = corpus[:1000]  # Test with 1k documents first
```

**Issue 3: BM25 scores seem too low/high**
```python
# Solution: Normalize scores before combining
from sklearn.preprocessing import MinMaxScaler

scaler = MinMaxScaler()
bm25_normalized = scaler.fit_transform(bm25_scores.reshape(-1, 1))
```

**Issue 4: Results don't match paper**
- Check embedding model (we used OpenAI ada-002)
- Verify query sets (benign queries should match corpus domain)
- Confirm threshold values (see paper Section 6.2.3)
- Try with larger corpus (we used 10k documents)

### Getting Help

- **GitHub Issues**: Open an issue with [Reproducibility] tag
- **Email**: [your-email]
- **Expected Response**: Within 1 week

---

## Citation

If you use this code or reproduce our results, please cite:

```bibtex
@article{thornton2025corpusdependent,
  title={Corpus-Dependent RAG Poisoning: Characterizing the Attack-Defense Trade-off in Retrieval-Augmented Generation Systems},
  author={Thornton, Scott},
  journal={arXiv preprint arXiv:XXXX.XXXXX},
  year={2025}
}
```

---

**Last Updated**: November 2025
**Status**: Complete reproducibility guide for defensive methods
**Note**: Attack implementations intentionally omitted for safety
