# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### March 2026 — AISec '26 Submission

**Multi-Model E2E Evaluation (5 LLMs)**:
- GPT-5.3: 46.7% attack success, 33.3% safety violations (strongest resistance)
- GPT-4o: 53.3% attack success, 86.7% safety violations
- GPT-4o-mini: 53.3% attack success, 86.7% safety violations
- Claude Sonnet 4.6: 60.0% attack success, 6.7% safety violations (strongest safety boundary)
- Llama 4 Instruct: 93.3% attack success, 93.3% safety violations (weakest)

**Joint Sparse+Dense Optimization**:
- Joint GCG optimization partially circumvents hybrid retrieval (20-44% success)
- Gradient-only attacks remain at 0% on hybrid (confirming prior results)
- Establishes hybrid retrieval as significant but not absolute defense

**FEVER Large-Scale Confirmation (n=25)**:
- 25 GCG attacks on FEVER Wikipedia sample
- 0% overall success across all retrieval configurations (pure vector and hybrid)
- Confirms n=9 cross-corpus pilot at 2.8× scale

**Added**:
- `experiments/` directory with self-contained experiment scripts
- `results/march-2026/` with all three experiment result files
- Updated README with March 2026 findings

### Initial Release

- Research repository for "Semantic Chameleon: Corpus-Dependent Poisoning Attacks and Defenses in RAG Systems"
- Published research paper with DOI (Zenodo: 10.5281/zenodo.18080200)
- Code implementation with DOI (Zenodo: 10.5281/zenodo.18079735)
- Defensive RAG security research materials
- Comprehensive detection and defense implementations

### December 2025 Updates

**End-to-End LLM Evaluation**:
- Demonstrated 60% attack success rate in production scenarios
- Measured 80% safety bypass rate when poisoned docs retrieved
- 46% average response divergence from clean context
- GPT-4o-mini testing shows RAG context overrides model safety training
- 73% refusal rate with clean context vs 60% attack success with poisoned context

**Production RAG Case Study**:
- Validated corpus-dependency hypothesis on 156,777-document corpus
- Real-world technical corpus evaluation
- Production-scale testing and analysis
- Corpus composition impact on defense effectiveness

### Research Contributions

**Key Findings**:
- **Co-Retrieval Success**: 38.0% on pure vector retrieval (n=50, 95% CI: 25.9%-51.8%)
- **Hybrid Retrieval Defense**: α≤0.5 reduces co-retrieval to 0% across 50 gradient-optimized attacks
- **Corpus Dependency**: Technical corpora 13-62× worse defense performance than general knowledge
- **Detection Method**: Query Pattern Differential most reliable across corpus types
- **Attack Success**: 60% end-to-end attack success rate in LLM evaluation
- **Safety Bypass**: 80% of successful attacks bypass LLM safety training

### Technical Implementation

**Attack Research** (`/detection` and `/defense`):
- Gradient-optimized poisoning attack implementations
- Dual-stage temporal poisoning methodology
- Vector space manipulation techniques
- Corpus-adaptive attack strategies
- Sanitized educational materials only

**Defense Mechanisms** (`/defense`):
- Hybrid BM25+vector retrieval (α parameter tuning)
- Query Pattern Differential detection
- Corpus-dependent defense strategies
- Real-time attack detection systems
- Production-ready defense implementations

**Evaluation Framework** (`/evaluation` and `/results`):
- Comprehensive benchmark suite
- Co-retrieval success rate measurement
- Detection performance metrics
- Cross-corpus evaluation
- End-to-end LLM attack assessment
- Production RAG case study methodology

### Research Methodology

**Corpus Analysis**:
- General knowledge bases (Wikipedia-style)
- Technical documentation corpora
- Mixed-domain datasets
- Production-scale corpus (156K+ documents)
- Corpus composition impact studies

**Attack Characterization**:
- Dual-stage temporal poisoning
- Semantic chameleon technique
- Gradient-based optimization
- Co-retrieval success measurement
- Safety bypass evaluation

**Defense Evaluation**:
- Hybrid retrieval architectures (BM25+vector)
- Alpha parameter optimization (α≤0.5 optimal)
- Detection method comparison
- False positive rate analysis
- Production deployment considerations

### Published Work

**Paper Publication**:
- DOI: 10.5281/zenodo.18080200
- Author: Scott Thornton (perfecXion.ai)
- Platform: Zenodo
- Full methodology and results documented

**Code Repository**:
- DOI: 10.5281/zenodo.18079735
- MIT License
- Open-source research code
- Reproducible experiments
- Educational materials

### Documentation

**Research Documentation** (`/docs` and `/paper`):
- Research paper and methodology
- Experimental design documentation
- Results analysis and interpretation
- Defense implementation guides
- Production deployment recommendations

**Example Implementations** (`/examples`):
- Attack detection examples
- Defense deployment samples
- Hybrid retrieval configurations
- Evaluation harness usage
- Integration patterns

**Citation Format** (`CITATION.cff`):
- Standard citation file format
- Academic attribution guidance
- BibTeX compatible
- DOI references included

### Security Research Focus

**Defensive Research Only**:
- No weaponized attack materials
- Sanitized educational content
- Focus on defense mechanisms
- Responsible disclosure practices
- Open-source defensive tools

**Corpus-Dependent Security**:
- Technical vs general corpus vulnerability analysis
- Architecture-dependent defense strategies
- Hybrid retrieval security benefits
- Detection method reliability by corpus type
- Production deployment considerations

### Results and Analysis

**Attack Success Metrics**:
- Pure vector retrieval: 38.0% co-retrieval success
- Hybrid retrieval (α≤0.5): 0% co-retrieval success
- End-to-end LLM: 60% attack success, 80% safety bypass
- Production corpus: Validates corpus-dependency hypothesis

**Defense Effectiveness**:
- Hybrid BM25+vector retrieval highly effective
- Query Pattern Differential: Most reliable detection
- Technical corpora 13-62× harder to defend
- Alpha parameter tuning critical for security
- Production-ready defense implementations validated

### Dependencies and Requirements

**Technical Stack**:
- Python 3.8+ for research code
- PyTorch for gradient-based optimization
- Vector database for retrieval testing
- BM25 implementation for hybrid retrieval
- Standard ML/NLP libraries (see requirements.txt)

**Evaluation Tools**:
- Retrieval evaluation harness
- Detection metric calculators
- Statistical analysis tools
- Visualization utilities
- Production case study framework

### License and Attribution

**MIT License**:
- Open-source research code
- Academic and commercial use permitted
- Attribution required (see CITATION.cff)
- Defensive research purposes

**Citation**:
```bibtex
See CITATION.cff for proper citation format
```

**Author**: Scott Thornton, perfecXion.ai

### Community and Contributions

**Research Transparency**:
- Open-source methodology
- Reproducible experiments
- Public datasets (sanitized)
- Comprehensive documentation
- Academic collaboration welcome

**Responsible Research**:
- Defensive focus only
- No attack weaponization
- Sanitized materials
- Ethical research practices
- Coordinated disclosure

[Unreleased]: https://github.com/scthornton/semantic-chameleon/commits/main
