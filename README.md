# Corpus-Dependent RAG Poisoning

[![Paper DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18080200.svg)](https://doi.org/10.5281/zenodo.18080200)
[![Code DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18079735.svg)](https://doi.org/10.5281/zenodo.18079735)

**Research Repository for "Semantic Chameleon: Corpus-Dependent Poisoning Attacks and Defenses in RAG Systems"**

⚠️ **DEFENSIVE RESEARCH ONLY**: This repository contains sanitized educational materials for understanding and defending against RAG poisoning attacks. No weaponized attack materials are included.

---

## 📄 Paper

**Paper (PDF)**: [https://doi.org/10.5281/zenodo.18080200](https://doi.org/10.5281/zenodo.18080200)

**Code (This Repo)**: [https://doi.org/10.5281/zenodo.18079735](https://doi.org/10.5281/zenodo.18079735)

**Author**: Scott Thornton (perfecXion.ai)

**Abstract**: This work characterizes how corpus composition and retrieval architecture jointly affect RAG security. We find that technical corpora are 13-62× harder to defend than general knowledge bases, and that simple hybrid BM25+vector retrieval neutralizes gradient-optimized attacks in our experiments.

**Key Findings**:
- 38.0% co-retrieval success on pure vector retrieval (n=50, 95% CI: 25.9%-51.8%)
- Hybrid retrieval (α≤0.5) reduces co-retrieval to 0% across all 50 gradient-optimized attacks in our setting
- Technical corpora show 13-62× worse detection performance than general knowledge bases
- Query Pattern Differential emerges as most reliable detection method across corpora
- **NEW (Dec 2025)**: End-to-end LLM evaluation shows 60% attack success rate, 80% safety bypass
- **NEW (Dec 2025)**: Production RAG case study (156,777 docs) validates corpus-dependency hypothesis

---

## 🆕 December 2025 Updates

### End-to-End LLM Evaluation (NEW)

We extended our evaluation to demonstrate that retrieved poisoned documents actually influence LLM output:

| Metric | Result |
|--------|--------|
| Attack Success Rate | 60% (9/15 scenarios) |
| Safety Bypass Rate | 80% of successful attacks |
| Response Divergence | 46% average |
| Model Tested | GPT-4o-mini |

**Key Insight**: Even with model safety training, RAG context can override guardrails. 73% of queries were refused with clean context, but 60% provided malicious instructions with poisoned context.

### Production RAG Case Study (NEW)

Validated corpus-dependency hypothesis against a real 156,777-document corpus:

| Attack Type | Retrieval Success | Trigger Rank |
|------------|-------------------|--------------|
| Naive (generic) | 0% | N/A |
| Adaptive (corpus-optimized) | 100% | #1 |

**Key Insight**: Attacks don't transfer across corpora. Naive attacks fail completely; adaptive attacks using the target embedding model succeed reliably.

---

## 📁 Repository Structure

```
semantic-chameleon/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── SECURITY.md                        # Responsible disclosure policy
│
├── detection/                         # Detection framework (defensive only)
│   ├── semantic_drift.py             # Method 1: Embedding anomaly detection
│   ├── keyword_anomaly.py            # Method 2: IDF-based keyword detection
│   ├── query_pattern.py              # Method 3: Query differential analysis
│   ├── detection_metrics.py          # ROC, F1, AUROC evaluation
│   └── README.md                     # Detection method documentation
│
├── defense/                           # Defense implementations
│   ├── hybrid_retrieval.py           # BM25+vector hybrid scoring
│   ├── bm25_implementation.py        # Okapi BM25 with configurable params
│   └── README.md                     # Defense deployment guide
│
├── evaluation/                        # Evaluation scripts
│   ├── metrics.py                    # Success rate, CI calculation (Wilson score)
│   ├── statistical_tests.py          # Chi-square, effect size (Cohen's h)
│   ├── corpus_analysis.py            # Corpus property analysis
│   ├── e2e_llm_evaluation.py         # NEW: End-to-end LLM evaluation
│   └── README.md                     # Evaluation methodology
│
├── examples/                          # Sanitized educational examples
│   ├── sanitized_scenarios.json      # Attack scenario descriptions (no exploits)
│   ├── benign_document_templates.txt # Example benign document structures
│   ├── detection_examples.py         # How to use detection framework
│   └── README.md                     # Examples documentation
│
├── data/                              # Dataset information (no actual data)
│   ├── security_se_instructions.md   # How to obtain Security Stack Exchange
│   ├── fever_instructions.md         # How to obtain FEVER dataset
│   └── corpus_statistics.json        # Corpus metadata (sizes, domains)
│
├── results/                           # NEW: Experimental results
│   ├── e2e_evaluation_results.json   # End-to-end LLM evaluation
│   ├── panw_case_study.json          # Production RAG case study
│   └── README.md                     # Results documentation
│
├── paper/                             # Paper materials
│   ├── paper.pdf                     # Main paper (arXiv version)
│   ├── supplementary.pdf             # Supplementary materials
│   └── figures/                      # Paper figures (PNG, 300 DPI)
│
├── docs/                              # Documentation
│   ├── REPRODUCIBILITY.md            # Step-by-step reproduction guide
│   ├── ETHICAL_CONSIDERATIONS.md     # Ethics and responsible use
│   ├── DEPLOYMENT_GUIDE.md           # How to deploy defenses
│   └── FAQ.md                        # Frequently asked questions
│
└── requirements.txt                   # Python dependencies
```

---

## 🛡️ Defensive Focus

This repository provides:

✅ **Detection methods** - 5 detection approaches with complete implementations
✅ **Defense mechanisms** - Hybrid retrieval and monitoring strategies
✅ **Evaluation tools** - Metrics, statistical tests, ROC analysis
✅ **Corpus analysis** - Understanding corpus-dependent security properties
✅ **Deployment guides** - Practical guidance for securing RAG systems

❌ **NOT included** - Working attack implementations, weaponizable exploits, malicious document generation

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/scthornton/semantic-chameleon
cd semantic-chameleon
pip install -r requirements.txt
```

### Run Detection Framework

```python
from detection.query_pattern import QueryPatternDetector
from defense.hybrid_retrieval import HybridRetriever

# Initialize detector
detector = QueryPatternDetector(
    benign_queries=100,  # Sample from production logs
    sensitive_queries=20  # Domain-specific attack patterns
)

# Initialize hybrid defense
retriever = HybridRetriever(alpha=0.5)  # Balanced BM25+vector

# Analyze corpus
results = detector.analyze_corpus(corpus, threshold=0.2)
print(f"Detected: {results['flagged_documents']} suspicious documents")
```

### Deploy Hybrid Defense

```python
from defense.hybrid_retrieval import HybridRetriever

# Security-critical configuration (recommended)
retriever = HybridRetriever(
    alpha=0.5,           # 50% vector, 50% BM25
    bm25_k1=1.5,         # Standard Okapi BM25
    bm25_b=0.75
)

# Retrieve with defense
results = retriever.retrieve(query, k=10)
```

---

## 📊 Reproducing Paper Results

See [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) for complete step-by-step instructions.

**High-level overview**:

1. **Obtain datasets**: Security Stack Exchange dump + FEVER dataset
2. **Run detection evaluation**: `python evaluation/run_detection.py`
3. **Test hybrid defense**: `python evaluation/run_hybrid_defense.py`
4. **Generate figures**: `python evaluation/generate_figures.py`

**Expected compute**: ~8-16 hours on GCP n1-standard-8 (or equivalent)

---

## 🔬 Research Ethics

This research follows responsible disclosure practices:

- **Defensive focus**: All materials prioritize understanding defenses
- **No weaponization**: Attack implementations are conceptual only
- **Sanitized examples**: All examples use non-exploitable scenarios
- **Coordinated disclosure**: Vulnerabilities reported to affected vendors

See [`docs/ETHICAL_CONSIDERATIONS.md`](docs/ETHICAL_CONSIDERATIONS.md) for full ethics statement.

---

## 📖 Citation

If you use this research or code, please cite:

```bibtex
@article{thornton2025semantic,
  author    = {Thornton, Scott},
  title     = {Semantic Chameleon: Corpus-Dependent Poisoning Attacks and Defenses in RAG Systems},
  year      = {2025},
  doi       = {10.5281/zenodo.18080200},
  url       = {https://doi.org/10.5281/zenodo.18080200},
  publisher = {Zenodo}
}
```

**Paper:** [https://doi.org/10.5281/zenodo.18080200](https://doi.org/10.5281/zenodo.18080200)
**Code:** [https://doi.org/10.5281/zenodo.18079735](https://doi.org/10.5281/zenodo.18079735)

---

## 🤝 Contributing

We welcome contributions that advance RAG security defenses:

- Detection method improvements
- New defense mechanisms
- Evaluation tools
- Documentation improvements

**Not accepted**: Attack implementations, weaponizable code, malicious examples

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines.

---

## 📧 Contact

**Scott Thornton**
- Website: https://perfecxion.ai
- Email: scott@perfecxion.ai
- Paper: [https://doi.org/10.5281/zenodo.18080200](https://doi.org/10.5281/zenodo.18080200)
- GitHub: https://github.com/scthornton/semantic-chameleon

**Security Issues**: Please report via [SECURITY.md](SECURITY.md)

---

## 📜 License

MIT License - see [`LICENSE`](LICENSE) for details.

**Responsible Use Clause**: By using this code, you agree to use it only for defensive security research, system hardening, and educational purposes. Malicious use is prohibited and violates the terms of this license.

---

## 🙏 Acknowledgments

- Security Stack Exchange community for public dataset
- FEVER dataset maintainers
- Google Cloud Platform for computational resources
- OpenAI for embedding API access

---

**Last Updated**: December 2025
**Paper DOI**: [10.5281/zenodo.18080200](https://doi.org/10.5281/zenodo.18080200)
**Code DOI**: [10.5281/zenodo.18079735](https://doi.org/10.5281/zenodo.18079735)
**Status**: Published on Zenodo (defensive research materials)
