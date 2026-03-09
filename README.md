# Corpus-Dependent RAG Poisoning

[![Paper DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18080200.svg)](https://doi.org/10.5281/zenodo.18080200)
[![Code DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18079735.svg)](https://doi.org/10.5281/zenodo.18079735)

**Research Repository for "Semantic Chameleon: Corpus-Dependent Poisoning Attacks and Defenses in RAG Systems"**

**DEFENSIVE RESEARCH ONLY**: This repository contains sanitized educational materials for understanding and defending against RAG poisoning attacks. No weaponized attack materials are included.

---

## Paper

**Paper (PDF)**: [https://doi.org/10.5281/zenodo.18080200](https://doi.org/10.5281/zenodo.18080200)

**Code (This Repo)**: [https://doi.org/10.5281/zenodo.18079735](https://doi.org/10.5281/zenodo.18079735)

**Anonymous Review Copy**: [https://anonymous.4open.science/r/semantic-chameleon-B610/](https://anonymous.4open.science/r/semantic-chameleon-B610/)

**Author**: Scott Thornton (perfecXion.ai)

**Abstract**: This work characterizes how corpus composition and retrieval architecture jointly affect RAG security. We find that technical corpora are 13-62× harder to defend than general knowledge bases, and that simple hybrid BM25+vector retrieval neutralizes gradient-optimized attacks in our experiments.

**Key Findings**:
- 38.0% co-retrieval success on pure vector retrieval (n=50, 95% CI: 25.9%-51.8%)
- Hybrid retrieval (α≤0.5) reduces co-retrieval to 0% across all 50 gradient-optimized attacks
- Joint sparse+dense optimization partially circumvents hybrid (20-44% success) but significantly raises the bar
- **Multi-model E2E** (5 LLMs): attack success 46.7% (GPT-5.3) to 93.3% (Llama 4); safety violations 6.7% (Claude) to 93.3% (Llama 4)
- **FEVER n=25**: 0% overall success across all retrieval configs, confirming corpus-dependent effects at scale
- Technical corpora show 13-62× worse detection performance than general knowledge bases
- Query Pattern Differential emerges as most reliable detection method across corpora

---

## March 2026 Updates (AISec '26 Submission)

### Multi-Model End-to-End Evaluation (5 LLMs)

Attack effectiveness varies dramatically across model families:

| Model | Attack Success | Safety Violations | Payload Leakage | Divergence |
|-------|---------------|-------------------|-----------------|------------|
| GPT-5.3 | **46.7%** (7/15) | 33.3% | 9.6% | 0.284 |
| GPT-4o | 53.3% (8/15) | 86.7% | 12.0% | 0.483 |
| GPT-4o-mini | 53.3% (8/15) | 86.7% | 14.9% | 0.418 |
| Claude Sonnet 4.6 | 60.0% (9/15) | **6.7%** | 5.7% | 0.196 |
| Llama 4 Instruct | **93.3%** (14/15) | **93.3%** | **56.8%** | 0.268 |

**Key Insight**: Safety training maturity varies dramatically. Claude shows the strongest safety boundary (6.7% violations despite 60% attack success). Llama 4 is dramatically vulnerable (93% attack success, only 27% clean refusal rate). GPT-5.3 shows measurable improvement over GPT-4o.

### Joint Sparse+Dense Optimization

A knowledgeable attacker who jointly optimizes for both BM25 and vector retrieval can partially circumvent hybrid defense:

| Attack Type | α=0.7 | α=0.5 | α=0.3 |
|-------------|-------|-------|-------|
| Gradient-only (baseline) | 0% | 0% | 0% |
| Joint optimization | **20%** | **36%** | **44%** |

**Key Insight**: Hybrid retrieval raises the attack bar from 38% (pure vector) to 0% (gradient-only on hybrid), but joint optimization achieves 20-44%. Hybrid retrieval is a significant defense, not an absolute one.

### FEVER Large-Scale (n=25)

25 GCG-optimized attacks on FEVER Wikipedia (2,000-doc representative sample):

| Config | Co-Retrieval | Stealth | Overall Success |
|--------|-------------|---------|-----------------|
| Pure Vector (α=1.0) | 100% | 0% | **0%** |
| Hybrid (α=0.7) | 100% | 0% | **0%** |
| Hybrid (α=0.5) | 100% | 0% | **0%** |
| Hybrid (α=0.3) | 100% | 0% | **0%** |

**Key Insight**: Confirms n=9 pilot at 2.8× scale. General-vocabulary corpora make attack documents conspicuous regardless of retrieval architecture.

---

## December 2025 Updates

### End-to-End LLM Evaluation (Single Model)

Initial evaluation against GPT-4o-mini (15 attack scenarios):

| Metric | Result |
|--------|--------|
| Attack Success Rate | 60% (9/15 scenarios) |
| Safety Bypass Rate | 80% of successful attacks |
| Response Divergence | 46% average |
| Model Tested | GPT-4o-mini |

### Production RAG Case Study

Validated corpus-dependency hypothesis against a 156,777-document production corpus:

| Attack Type | Retrieval Success | Trigger Rank |
|------------|-------------------|--------------|
| Naive (generic) | 0% | N/A |
| Adaptive (corpus-optimized) | 100% | #1 |

---

## Repository Structure

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
├── experiments/                        # Experiment scripts (March 2026)
│   ├── exp1_fever_large_scale.py     # FEVER n=25 evaluation
│   ├── exp2_multimodel_e2e.py        # Multi-model E2E (5 LLMs)
│   ├── exp3_joint_hybrid_attack.py   # Joint sparse+dense optimization
│   ├── setup_data.py                 # Data download and embedding setup
│   └── requirements.txt              # Experiment dependencies
│
├── results/                           # Experimental results
│   ├── e2e_evaluation_results.json   # Dec 2025: E2E LLM evaluation
│   ├── panw_case_study.json          # Dec 2025: Production case study
│   ├── march-2026/                   # March 2026 experiments
│   │   ├── exp1_fever_large_scale_results.json
│   │   ├── exp2_multimodel_e2e_results.json
│   │   └── exp3_joint_hybrid_attack_results.json
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

## Defensive Focus

This repository provides:

- **Detection methods** - 5 detection approaches with complete implementations
- **Defense mechanisms** - Hybrid retrieval and monitoring strategies
- **Evaluation tools** - Metrics, statistical tests, ROC analysis
- **Corpus analysis** - Understanding corpus-dependent security properties
- **Deployment guides** - Practical guidance for securing RAG systems

**NOT included** - Working attack implementations, weaponizable exploits, malicious document generation

---

## Quick Start

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

## Reproducing Paper Results

See [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md) for complete step-by-step instructions.

**High-level overview**:

1. **Obtain datasets**: Security Stack Exchange dump + FEVER dataset
2. **Run detection evaluation**: `python evaluation/run_detection.py`
3. **Test hybrid defense**: `python evaluation/run_hybrid_defense.py`
4. **Generate figures**: `python evaluation/generate_figures.py`

**Expected compute**: ~8-16 hours on GCP n1-standard-8 (or equivalent)

---

## Research Ethics

This research follows responsible disclosure practices:

- **Defensive focus**: All materials prioritize understanding defenses
- **No weaponization**: Attack implementations are conceptual only
- **Sanitized examples**: All examples use non-exploitable scenarios
- **Coordinated disclosure**: Vulnerabilities reported to affected vendors

See [`docs/ETHICAL_CONSIDERATIONS.md`](docs/ETHICAL_CONSIDERATIONS.md) for full ethics statement.

---

## Citation

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

## Contributing

We welcome contributions that advance RAG security defenses:

- Detection method improvements
- New defense mechanisms
- Evaluation tools
- Documentation improvements

**Not accepted**: Attack implementations, weaponizable code, malicious examples

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines.

---

## Contact

**Scott Thornton**
- Website: https://perfecxion.ai
- Email: scott@perfecxion.ai
- Paper: [https://doi.org/10.5281/zenodo.18080200](https://doi.org/10.5281/zenodo.18080200)
- GitHub: https://github.com/scthornton/semantic-chameleon

**Security Issues**: Please report via [SECURITY.md](SECURITY.md)

---

## License

MIT License - see [`LICENSE`](LICENSE) for details.

**Responsible Use Clause**: By using this code, you agree to use it only for defensive security research, system hardening, and educational purposes. Malicious use is prohibited and violates the terms of this license.

---

## Acknowledgments

- Security Stack Exchange community for public dataset
- FEVER dataset maintainers
- Google Cloud Platform for computational resources
- OpenAI for embedding API access

---

**Last Updated**: March 2026
**Paper DOI**: [10.5281/zenodo.18080200](https://doi.org/10.5281/zenodo.18080200)
**Code DOI**: [10.5281/zenodo.18079735](https://doi.org/10.5281/zenodo.18079735)
**Status**: Published on Zenodo (defensive research materials)
