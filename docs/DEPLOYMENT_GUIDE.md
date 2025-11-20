# Deployment Guide: Securing RAG Systems Against Poisoning

This guide provides step-by-step instructions for deploying RAG poisoning defenses in production environments.

**Target Audience**: DevOps engineers, security teams, RAG system operators

**Time Required**: 4-8 hours for initial deployment, ongoing monitoring

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Architecture Overview](#architecture-overview)
3. [Primary Defense: Hybrid Retrieval](#primary-defense-hybrid-retrieval)
4. [Secondary Defense: Detection Monitoring](#secondary-defense-detection-monitoring)
5. [Production Deployment](#production-deployment)
6. [Performance Considerations](#performance-considerations)
7. [Monitoring and Alerting](#monitoring-and-alerting)
8. [Incident Response](#incident-response)

---

## Quick Start

### Minimum Viable Defense (30 minutes)

Deploy hybrid retrieval immediately - this neutralizes gradient-optimized attacks:

```python
from defense.hybrid_retrieval import HybridRetriever

# Security-critical configuration (RECOMMENDED)
retriever = HybridRetriever(
    alpha=0.5,        # 50% vector, 50% BM25
    bm25_k1=1.5,      # Standard Okapi BM25
    bm25_b=0.75
)

# Replace your pure vector retrieval with:
results = retriever.retrieve(query, corpus, k=10)
```

**Impact**: Paper results show 0% co-retrieval across all 50 gradient-optimized attacks with α ≤ 0.5

---

## Architecture Overview

### Defense Layers

```
┌─────────────────────────────────────────────────────────┐
│                    User Query                           │
└─────────────────────┬───────────────────────────────────┘
                      │
          ┌───────────▼──────────┐
          │  Hybrid Retrieval    │  ← PRIMARY DEFENSE
          │  (BM25 + Vector)     │    0% attack success (α≤0.5)
          └───────────┬──────────┘
                      │
          ┌───────────▼──────────┐
          │  Retrieved Documents │
          └───────────┬──────────┘
                      │
          ┌───────────▼──────────┐
          │  Detection Monitor   │  ← SECONDARY DEFENSE
          │  (Query Pattern)     │    Continuous monitoring
          └───────────┬──────────┘
                      │
          ┌───────────▼──────────┐
          │  LLM Generation      │
          └──────────────────────┘
```

### Threat Model

**What we defend against**:
- ✅ Gradient-optimized poisoning (dual-document attacks)
- ✅ Semantic manipulation attacks
- ✅ Adversarially crafted documents
- ✅ Co-retrieval exploitation

**What we don't defend against** (out of scope):
- ❌ Prompt injection in LLM generation stage (orthogonal attack)
- ❌ Model extraction attacks
- ❌ Denial of service attacks
- ❌ Unauthorized corpus modifications (infrastructure security)

---

## Primary Defense: Hybrid Retrieval

### Step 1: Assess Your Current Setup

Identify your embedding model and retrieval infrastructure:

```python
# Current setup (vulnerable)
query_embedding = embed_model.encode(query)
similarities = cosine_similarity(query_embedding, corpus_embeddings)
top_k_indices = np.argsort(similarities)[-k:]
```

### Step 2: Choose Your Configuration

**Security-Critical Systems** (banking, healthcare, legal):
```python
retriever = HybridRetriever(alpha=0.5)  # Balanced defense
# 50% vector, 50% BM25
# Paper validation: 0% attack success
```

**General Purpose Systems**:
```python
retriever = HybridRetriever(alpha=0.6)  # Slight semantic preference
# 60% vector, 40% BM25
# Paper validation: 0% attack success
```

**Maximum Defense** (paranoid mode):
```python
retriever = HybridRetriever(alpha=0.3)  # BM25-heavy
# 30% vector, 70% BM25
# Paper validation: 0% attack success
# Trade-off: Reduced semantic flexibility
```

### Step 3: Integration Patterns

#### Pattern A: Drop-in Replacement

Replace your existing retrieval with hybrid scoring:

```python
# BEFORE (vulnerable)
def retrieve(query, corpus, k=10):
    query_vec = embed(query)
    scores = [cosine_similarity(query_vec, embed(doc)) for doc in corpus]
    return top_k(scores, k)

# AFTER (defended)
from defense.hybrid_retrieval import HybridRetriever

retriever = HybridRetriever(alpha=0.5)

def retrieve(query, corpus, k=10):
    return retriever.retrieve(query, corpus, k)
```

#### Pattern B: With Vector Database

Integrate with existing vector database infrastructure:

```python
from defense.hybrid_retrieval import HybridRetriever
import pinecone  # or qdrant, weaviate, etc.

# Initialize components
vector_db = pinecone.Index("my-index")
retriever = HybridRetriever(alpha=0.5)

def hybrid_retrieve(query, k=10):
    # Step 1: Vector search (get top 2k candidates)
    query_vec = embed(query)
    vector_results = vector_db.query(query_vec, top_k=k*2)

    # Step 2: Re-rank with hybrid scoring
    candidates = [
        {'id': r.id, 'content': r.metadata['text']}
        for r in vector_results
    ]

    # Step 3: Hybrid re-ranking
    final_results = retriever.retrieve(query, candidates, k=k)

    return final_results
```

#### Pattern C: Elasticsearch Integration

Leverage Elasticsearch's native BM25:

```python
from elasticsearch import Elasticsearch

es = Elasticsearch()

def hybrid_retrieve_elasticsearch(query, k=10, alpha=0.5):
    # Get BM25 scores from Elasticsearch
    bm25_results = es.search(
        index="my-corpus",
        body={
            "query": {"match": {"content": query}},
            "size": k * 2
        }
    )

    # Get vector scores from your embedding model
    query_vec = embed(query)

    # Combine scores
    hybrid_scores = []
    for hit in bm25_results['hits']['hits']:
        doc_vec = embed(hit['_source']['content'])
        vector_score = cosine_similarity(query_vec, doc_vec)
        bm25_score = hit['_score']

        # Normalize and combine
        vector_norm = (vector_score + 1) / 2  # [-1,1] -> [0,1]
        bm25_norm = bm25_score / max_bm25_score

        hybrid_score = alpha * vector_norm + (1 - alpha) * bm25_norm
        hybrid_scores.append((hit['_id'], hybrid_score))

    # Sort and return top k
    hybrid_scores.sort(key=lambda x: x[1], reverse=True)
    return hybrid_scores[:k]
```

### Step 4: Validation

Test your deployment before production:

```python
# Generate test queries
test_queries = [
    "What is authentication?",
    "How to implement MFA?",
    # ... 10-20 representative queries
]

# Compare pure vector vs hybrid
for query in test_queries:
    vector_results = old_retrieve(query, k=10)
    hybrid_results = retriever.retrieve(query, corpus, k=10)

    # Check overlap (should be high for benign queries)
    overlap = len(set(vector_results) & set(hybrid_results)) / 10
    print(f"Query: {query}")
    print(f"  Overlap: {overlap:.0%}")

    # Low overlap (<50%) may indicate corpus issues
    if overlap < 0.5:
        print(f"  ⚠ WARNING: Low overlap, review corpus quality")
```

---

## Secondary Defense: Detection Monitoring

### Step 1: Choose Detection Method

Based on your corpus type:

```python
# For general knowledge corpora (Wikipedia, news, encyclopedias)
from detection.query_pattern import QueryPatternDetector
from detection.keyword_anomaly import KeywordAnomalyDetector

primary_detector = QueryPatternDetector(...)
secondary_detector = KeywordAnomalyDetector(...)  # Optional

# For technical corpora (Stack Exchange, code repos, API docs)
from detection.query_pattern import QueryPatternDetector

primary_detector = QueryPatternDetector(...)
# NOTE: Keyword Anomaly NOT recommended for technical corpora
```

### Step 2: Generate Query Sets

**Benign Queries** (sample from production):

```python
# Option A: Sample from production logs
benign_queries = sample_from_logs(
    log_file="query_logs.json",
    num_samples=100,
    time_window="30 days"
)

# Option B: Sample from corpus titles/questions
benign_queries = [
    doc['title'] for doc in corpus
    if 'title' in doc
][:100]
```

**Sensitive Queries** (craft for your threats):

```python
# Customize for YOUR threat model
sensitive_queries = [
    # Authentication attacks
    "bypass authentication in enterprise systems",
    "circumvent MFA requirements",

    # Data exfiltration
    "extract sensitive data from databases",
    "access confidential information",

    # Add 15-20 queries per attack family relevant to YOUR domain
]
```

### Step 3: Run Initial Scan

Scan existing corpus for poisoned documents:

```python
from detection.query_pattern import QueryPatternDetector

detector = QueryPatternDetector(
    benign_queries=benign_queries,
    sensitive_queries=sensitive_queries
)

# Scan corpus
threshold = detector.recommend_threshold('technical')  # or 'general'
results = detector.analyze_corpus(corpus, threshold=threshold)

print(f"Flagged: {results['total_flagged']} documents")
print(f"Expected FPR: {results['expected_performance']['expected_fpr']:.4f}")

# Investigate flagged documents
for doc in results['flagged_documents']:
    print(f"\n{doc.document_id}:")
    print(f"  Benign rate: {doc.benign_retrieval_rate:.3f}")
    print(f"  Sensitive rate: {doc.sensitive_retrieval_rate:.3f}")
    print(f"  Differential: {doc.differential_score:.3f}")
```

### Step 4: Continuous Monitoring

Set up ongoing detection for new documents:

```python
def monitor_new_documents(new_docs, detector, threshold):
    """
    Monitor newly added documents for poisoning.
    Run this on document ingestion pipeline.
    """
    # Analyze new documents
    results = detector.analyze_corpus(new_docs, threshold=threshold)

    if results['total_flagged'] > 0:
        # Alert security team
        alert_security_team(
            flagged_docs=results['flagged_documents'],
            severity='HIGH' if results['total_flagged'] > 5 else 'MEDIUM'
        )

        # Quarantine flagged documents
        for doc in results['flagged_documents']:
            quarantine_document(doc.document_id)

        # Log for investigation
        log_incident(results)

    return results

# Example: Monitor daily ingestion
new_docs = fetch_documents_added_since(last_check_time)
if new_docs:
    monitor_new_documents(new_docs, detector, threshold)
```

---

## Production Deployment

### Deployment Checklist

- [ ] **Hybrid retrieval deployed** with α ≤ 0.5
- [ ] **Initial corpus scan completed** and flagged documents reviewed
- [ ] **Continuous monitoring active** for new documents
- [ ] **Alerting configured** for detection events
- [ ] **Incident response procedures** documented
- [ ] **Performance validated** (latency, throughput acceptable)
- [ ] **Backup/rollback plan** in place
- [ ] **Team trained** on monitoring and response

### Infrastructure Requirements

**Compute**:
- Hybrid retrieval: +20-40% CPU vs pure vector (BM25 computation)
- Detection monitoring: Batch process, ~1-2 hours per 100k documents

**Storage**:
- BM25 index: ~10-20% of corpus size (inverted index)
- Detection logs: ~1MB per 1000 documents analyzed

**Latency Impact**:
- Per-query: +5-15ms (BM25 scoring)
- Mitigate with caching, pre-computed indices

### Scaling Patterns

**Small Scale** (<10k documents):
```python
# In-memory hybrid retrieval
retriever = HybridRetriever(alpha=0.5)
results = retriever.retrieve(query, corpus, k=10)
```

**Medium Scale** (10k-1M documents):
```python
# Use rank-bm25 library + FAISS
from rank_bm25 import BM25Okapi
import faiss

# Pre-compute indices
bm25_index = BM25Okapi(tokenized_corpus)
faiss_index = faiss.IndexFlatIP(embedding_dim)

# Query-time hybrid scoring
def retrieve_medium_scale(query, k=10):
    # BM25 scores
    bm25_scores = bm25_index.get_scores(tokenize(query))

    # Vector scores
    query_vec = embed(query)
    vector_scores, indices = faiss_index.search(query_vec, k*2)

    # Combine and rank
    hybrid_scores = combine_scores(bm25_scores, vector_scores, alpha=0.5)
    return top_k(hybrid_scores, k)
```

**Large Scale** (>1M documents):
```python
# Use Elasticsearch + Pinecone/Qdrant
# See Pattern C above
```

---

## Performance Considerations

### Query Latency

**Baseline** (pure vector):
- Vector search: 10-50ms (depends on index type)
- Total: 10-50ms

**With Hybrid Retrieval**:
- Vector search: 10-50ms
- BM25 scoring: 5-15ms (candidate re-ranking)
- Hybrid combination: 1-2ms
- **Total: 16-67ms** (+20-40% latency)

### Optimization Strategies

1. **Pre-filter with vector search**:
   ```python
   # Retrieve 2k candidates with vector search (fast)
   candidates = vector_search(query, k=2000)

   # Re-rank top candidates with hybrid scoring
   results = hybrid_rank(query, candidates, k=10)
   ```

2. **Cache BM25 term frequencies**:
   ```python
   # Pre-compute and cache document statistics
   bm25_cache = precompute_bm25_stats(corpus)

   # Query-time: lookup only
   bm25_scores = bm25_cache.score(query, doc_ids)
   ```

3. **Asynchronous detection**:
   ```python
   # Don't block retrieval on detection
   results = hybrid_retrieve(query, k=10)

   # Run detection asynchronously
   asyncio.create_task(
       monitor_retrieval(query, results)
   )

   return results
   ```

### Throughput Impact

- **Pure vector**: 1000 queries/sec (baseline)
- **Hybrid retrieval**: 700-850 queries/sec (-15-30%)
- **Mitigation**: Horizontal scaling, caching

---

## Monitoring and Alerting

### Metrics to Track

1. **Defense Effectiveness**:
   ```python
   # Track hybrid scoring distribution
   metrics = {
       'vector_score_mean': np.mean(vector_scores),
       'bm25_score_mean': np.mean(bm25_scores),
       'hybrid_score_mean': np.mean(hybrid_scores),
       'score_correlation': np.corrcoef(vector_scores, bm25_scores)[0,1]
   }
   ```

2. **Detection Performance**:
   ```python
   # Track detection flags
   metrics = {
       'documents_scanned': len(corpus),
       'flagged_count': len(flagged),
       'flagging_rate': len(flagged) / len(corpus),
       'false_positive_estimate': expected_fpr * len(corpus)
   }
   ```

3. **System Health**:
   ```python
   # Track operational metrics
   metrics = {
       'query_latency_p50': percentile(latencies, 50),
       'query_latency_p99': percentile(latencies, 99),
       'throughput_qps': queries_per_second,
       'error_rate': errors / total_queries
   }
   ```

### Alert Conditions

**Critical Alerts**:
```python
# Spike in flagged documents (potential attack)
if flagged_rate > baseline_rate * 3:
    alert(severity='CRITICAL', msg='Possible corpus poisoning attack')

# Detection system failure
if monitoring_errors > threshold:
    alert(severity='CRITICAL', msg='Detection system offline')
```

**Warning Alerts**:
```python
# Elevated flagging rate
if flagged_rate > baseline_rate * 1.5:
    alert(severity='WARNING', msg='Elevated detection rate')

# Performance degradation
if query_latency_p99 > sla_threshold:
    alert(severity='WARNING', msg='Query latency exceeds SLA')
```

---

## Incident Response

### When Detection Flags a Document

1. **Quarantine immediately**:
   ```python
   def quarantine_document(doc_id):
       # Remove from retrieval corpus
       corpus.remove(doc_id)

       # Move to quarantine storage
       quarantine_storage.put(doc_id, corpus[doc_id])

       # Log incident
       log_incident(doc_id, reason='detection_flag')
   ```

2. **Manual review**:
   - Read document content
   - Check author/source
   - Review retrieval patterns
   - Assess maliciousness

3. **Investigate scope**:
   ```python
   # Check for similar documents
   similar = find_similar_documents(flagged_doc, corpus)

   # Check author's other contributions
   author_docs = get_documents_by_author(flagged_doc.author)

   # Re-scan with lower threshold
   extended_scan = detector.analyze_corpus(
       similar + author_docs,
       threshold=threshold * 0.8
   )
   ```

4. **Remediate**:
   - Delete confirmed malicious documents
   - Block malicious contributors
   - Update detection rules if needed
   - Re-deploy corpus

### Playbook Template

```markdown
# RAG Poisoning Incident Response Playbook

## Phase 1: Detection (0-15 minutes)
- [ ] Alert received and acknowledged
- [ ] Incident ticket created
- [ ] On-call security engineer engaged
- [ ] Flagged documents quarantined automatically

## Phase 2: Assessment (15-60 minutes)
- [ ] Manual review of flagged content
- [ ] Scope assessment (how many documents affected?)
- [ ] Attack vector identification
- [ ] Impact analysis (which queries affected?)

## Phase 3: Containment (1-4 hours)
- [ ] Remove confirmed malicious documents
- [ ] Block attack vectors (IP, user account, upload method)
- [ ] Re-scan corpus with extended detection
- [ ] Deploy updated corpus to production

## Phase 4: Recovery (4-24 hours)
- [ ] Validate clean corpus
- [ ] Monitor for recurrence
- [ ] Update detection rules
- [ ] Document incident

## Phase 5: Post-Incident (1-7 days)
- [ ] Root cause analysis
- [ ] Update procedures
- [ ] Team retrospective
- [ ] Implement preventive measures
```

---

## Next Steps

1. **Deploy hybrid retrieval** today (30 minutes)
2. **Run initial corpus scan** this week (2-4 hours)
3. **Set up continuous monitoring** this sprint (4-8 hours)
4. **Document incident procedures** this month
5. **Train team on response** this quarter

---

## Support and Resources

- **GitHub Issues**: Report bugs or ask questions
- **Security Contact**: [your-security-email]
- **Documentation**: See `docs/REPRODUCIBILITY.md` for technical details
- **Paper**: See paper.pdf for research methodology

---

**Last Updated**: November 2025
**Status**: Production-ready defensive implementations
