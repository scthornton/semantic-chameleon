# Experimental Results

This directory contains the results from our experiments.

## End-to-End LLM Evaluation

**File**: `e2e_evaluation_results.json`

We tested whether poisoned documents retrieved by RAG systems actually influence LLM output. Testing 15 attack scenarios against GPT-4o-mini:

| Metric | Result |
|--------|--------|
| Attack Success Rate | 60.0% (9/15) |
| Safety Violation Rate | 80.0% (12/15) |
| Avg Payload Leakage | 19.0% |
| Avg Response Divergence | 0.46 |

### Key Observations

1. **Clean context behavior**: 73% refusal rate ("I cannot assist with that")
2. **Poisoned context behavior**: 60% provided actionable attack instructions
3. **Sleeper-only behavior**: 87% refused (confirms dual-document attack design)

### Successful Attack Categories

- AMSI bypass, API rate limiting, DLL sideloading
- DNS tunneling, GraphQL introspection, HTTP smuggling
- ICMP covert channel, insecure deserialization, JWT algorithm confusion

### Failed Attack Categories (model safety held)

- Alternate data streams, blockchain reentrancy
- Command injection, CSRF bypass
- Directory traversal, domain fronting

## Production RAG Case Study

**File**: `panw_case_study.json`

We validated our corpus-dependency hypothesis against a production-scale documentation RAG system containing 156,777 documents.

### Naive Attack Results (0% success)

Attack documents optimized for Security SE/FEVER corpora using OpenAI embeddings:
- Sleeper retrieval: 0%
- Trigger retrieval: 0%
- Any retrieval: 0%

### Adaptive Attack Results (100% success)

Attack documents optimized for target corpus using `all-MiniLM-L6-v2`:
- Sleeper retrieval: 100%
- Trigger retrieval: 100%
- Co-retrieval: 100%
- Average trigger rank: #1

### Implications

1. **Attacks don't transfer**: Must be tailored to target corpus
2. **Embedding model knowledge required**: Attackers need to know the target model
3. **Hybrid retrieval still effective**: Even adaptive attacks fail against hybrid BM25+vector

## Reproduction

See `docs/REPRODUCIBILITY.md` for instructions on reproducing these results.

Note: Raw attack scenarios are not included to prevent weaponization. Contact authors for research access.
