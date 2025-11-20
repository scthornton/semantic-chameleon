# Corpus-Dependent RAG Poisoning

**Research Repository for "Corpus-Dependent RAG Poisoning: Characterizing the Attack-Defense Trade-off in Retrieval-Augmented Generation Systems"**

⚠️ **DEFENSIVE RESEARCH ONLY**: This repository contains sanitized educational materials for understanding and defending against RAG poisoning attacks. No weaponized attack materials are included.

---

## 📄 Paper

**arXiv**: [Link pending]

**Authors**: Scott Thornton

**Abstract**: This work characterizes how corpus composition and retrieval architecture jointly affect RAG security. We find that technical corpora are 13-62× harder to defend than general knowledge bases, and that simple hybrid BM25+vector retrieval neutralizes gradient-optimized attacks in our experiments.

**Key Findings**:
- 38.0% co-retrieval success on pure vector retrieval (n=50, 95% CI: 25.9%-51.8%)
- Hybrid retrieval (α≤0.5) reduces co-retrieval to 0% across all 50 gradient-optimized attacks in our setting
- Technical corpora show 13-62× worse detection performance than general knowledge bases
- Query Pattern Differential emerges as most reliable detection method across corpora

---

## 📁 Repository Structure

```
corpus-dependent-rag-poisoning/
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
├── examples/                          # Sanitized educational examples
│   ├── sanitized_scenarios.json      # Attack scenario descriptions (no exploits)
│   ├── benign_document_templates.txt # Example benign document structures
│   ├── detection_examples.py         # How to use detection framework
│   └── README.md                     # Examples documentation
│
├── evaluation/                        # Evaluation scripts
│   ├── metrics.py                    # Success rate, CI calculation (Wilson score)
│   ├── statistical_tests.py          # Chi-square, effect size (Cohen's h)
│   ├── corpus_analysis.py            # Corpus property analysis
│   └── README.md                     # Evaluation methodology
│
├── data/                              # Dataset information (no actual data)
│   ├── security_se_instructions.md   # How to obtain Security Stack Exchange
│   ├── fever_instructions.md         # How to obtain FEVER dataset
│   └── corpus_statistics.json        # Corpus metadata (sizes, domains)
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
git clone https://github.com/yourusername/corpus-dependent-rag-poisoning
cd corpus-dependent-rag-poisoning
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
@article{thornton2025corpusdependent,
  title={Corpus-Dependent RAG Poisoning: Characterizing the Attack-Defense Trade-off in Retrieval-Augmented Generation Systems},
  author={Thornton, Scott},
  journal={arXiv preprint arXiv:XXXX.XXXXX},
  year={2025}
}
```

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
- Email: [scthornton -at- gmail]
- arXiv: [Link pending]

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

**Last Updated**: November 2025
**Paper Status**: Under review
**Code Status**: Sanitized educational release (defensive materials only)

