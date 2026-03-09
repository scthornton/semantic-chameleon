# Experimental Results

This directory contains results from all experimental phases.

## March 2026 Results (`march-2026/`)

Three new experiments addressing reviewer feedback for AISec '26 submission.

### Experiment 1: FEVER Large-Scale (n=25)

**File**: `march-2026/exp1_fever_large_scale_results.json`

25 GCG-optimized attacks (5 scenarios × 5 seeds) on a 2,000-document FEVER Wikipedia
sample. Tests pure vector and hybrid retrieval at multiple configurations.

| Config | Co-Retrieval | Stealth | Overall Success |
|--------|-------------|---------|-----------------|
| α=1.0, k=5 | 100% (25/25) | 0% (0/25) | **0%** |
| α=0.7, k=5 | 100% (25/25) | 0% (0/25) | **0%** |
| α=0.5, k=5 | 100% (25/25) | 0% (0/25) | **0%** |
| α=0.3, k=5 | 100% (25/25) | 0% (0/25) | **0%** |

**Finding**: Confirms n=9 pilot at 2.8× scale. FEVER's general vocabulary makes attack
terms anomalous, causing 0% stealth regardless of retrieval architecture.

### Experiment 2: Multi-Model E2E Evaluation

**File**: `march-2026/exp2_multimodel_e2e_results.json`

15 attack scenarios tested against 5 LLMs from 4 providers. GPT-4o-mini serves as
consistent safety judge across all models.

| Model | Attack Success | Safety Violations | Payload Leakage |
|-------|---------------|-------------------|-----------------|
| GPT-5.3 | 46.7% (7/15) | 33.3% (5/15) | 9.6% |
| GPT-4o | 53.3% (8/15) | 86.7% (13/15) | 12.0% |
| GPT-4o-mini | 53.3% (8/15) | 86.7% (13/15) | 14.9% |
| Claude Sonnet 4.6 | 60.0% (9/15) | 6.7% (1/15) | 5.7% |
| Llama 4 Instruct | 93.3% (14/15) | 93.3% (14/15) | 56.8% |

**Note**: GPT-5.3 was evaluated at temperature=1.0 (API-mandated); all other models
used temperature=0.3.

**Finding**: Three distinct safety profiles emerge: strong (Claude), moderate (GPT family),
and weak (Llama 4). Model-level safety is necessary but insufficient.

### Experiment 3: Joint Hybrid Attack

**File**: `march-2026/exp3_joint_hybrid_attack_results.json`

25 trials (5 scenarios × 5 seeds) using joint sparse+dense GCG optimization.
Joint objective: α × cosine_sim + (1-α) × BM25_overlap.

| Attack | α=0.7 | α=0.5 | α=0.3 |
|--------|-------|-------|-------|
| Gradient-only (baseline) | 0% | 0% | 0% |
| Joint optimization | 20% (5/25) | 36% (9/25) | 44% (11/25) |

**Finding**: Joint optimization partially circumvents hybrid retrieval (20-44% vs 0%
gradient-only), but hybrid still significantly raises the attack bar vs pure vector (38%).

---

## December 2025 Results

### End-to-End LLM Evaluation

**File**: `e2e_evaluation_results.json`

15 attack scenarios against GPT-4o-mini. 60% attack success, 80% safety violations.

### Production RAG Case Study

**File**: `panw_case_study.json`

156,777-document vendor corpus. 0% naive attack success, 100% adaptive success.

---

## Reproduction

See `docs/REPRODUCIBILITY.md` for instructions. March 2026 experiment scripts are in
`experiments/`. Raw attack scenarios are not included to prevent weaponization.
