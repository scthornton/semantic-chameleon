#!/usr/bin/env python3
"""
Data Setup Script - Downloads and prepares corpora for experiments.

Run this FIRST before any experiments.

Downloads:
  - FEVER Wikipedia corpus (for Experiment 1)
  - Computes embeddings for corpus samples (OpenAI API required)
"""

import json
import os
import time
import numpy as np
from pathlib import Path

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
EMBEDDING_MODEL = "text-embedding-3-small"
DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)


def download_fever_corpus(n_docs: int = 2000):
    """Download FEVER Wikipedia corpus from HuggingFace and sample."""
    output_file = DATA_DIR / "fever_corpus_sample.json"
    if output_file.exists():
        print(f"FEVER corpus sample already exists: {output_file}")
        return

    print("Downloading FEVER Wikipedia corpus from HuggingFace...")
    print("(This requires the 'datasets' package: pip install datasets)")

    try:
        from datasets import load_dataset
    except ImportError:
        print("\nERROR: 'datasets' package not installed.")
        print("Install with: pip install datasets")
        print("\nAlternatively, manually create data/fever_corpus_sample.json")
        print("with a JSON list of objects: [{\"text\": \"...\"}, ...]")
        return

    # FEVER uses Wikipedia passages
    print("Loading dataset (this may take a few minutes on first run)...")
    dataset = load_dataset("fever", "wiki_pages", split="wikipedia_pages",
                           trust_remote_code=True)

    # Sample diverse documents
    print(f"Dataset size: {len(dataset)}")
    indices = np.random.RandomState(42).choice(len(dataset), size=min(n_docs, len(dataset)),
                                                replace=False)

    docs = []
    for idx in indices:
        item = dataset[int(idx)]
        text = item.get('text', '')
        if len(text) > 50:
            docs.append({"text": text[:1000]})  # Truncate for efficiency

    with open(output_file, 'w') as f:
        json.dump(docs, f)

    print(f"Saved {len(docs)} FEVER documents to {output_file}")


def compute_embeddings(texts_file: str, output_prefix: str):
    """Compute OpenAI embeddings for a corpus sample."""
    from openai import OpenAI

    if not OPENAI_API_KEY:
        print("ERROR: OPENAI_API_KEY not set")
        return

    client = OpenAI(api_key=OPENAI_API_KEY)

    emb_file = DATA_DIR / f"{output_prefix}_embeddings_sample.npz"
    if emb_file.exists():
        print(f"Embeddings already exist: {emb_file}")
        return

    texts_path = DATA_DIR / texts_file
    if not texts_path.exists():
        print(f"ERROR: {texts_path} not found")
        return

    with open(texts_path) as f:
        data = json.load(f)

    # Extract text
    if isinstance(data[0], dict):
        texts = [d.get('text', str(d)) for d in data]
    else:
        texts = data

    print(f"Computing embeddings for {len(texts)} documents...")
    batch_size = 100
    all_embeddings = []

    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        response = client.embeddings.create(input=batch, model=EMBEDDING_MODEL)
        embeddings = []
        for item in response.data:
            emb = np.array(item.embedding, dtype=np.float32)
            norm = np.linalg.norm(emb)
            embeddings.append(emb / norm if norm > 0 else emb)
        all_embeddings.extend(embeddings)
        print(f"  Embedded {min(i+batch_size, len(texts))}/{len(texts)}")
        time.sleep(0.5)

    embeddings_array = np.array(all_embeddings)
    np.savez(emb_file, embeddings=embeddings_array)
    print(f"Saved embeddings ({embeddings_array.shape}) to {emb_file}")


def main():
    print("=" * 60)
    print("EXPERIMENT DATA SETUP")
    print("=" * 60)

    # Step 1: Download FEVER corpus
    print("\n[1/4] FEVER corpus...")
    download_fever_corpus(n_docs=2000)

    # Step 2: Compute FEVER embeddings
    print("\n[2/4] FEVER embeddings...")
    compute_embeddings("fever_corpus_sample.json", "fever")

    # Step 3: Security SE embeddings (texts already included in package)
    print("\n[3/4] Security SE embeddings...")
    compute_embeddings("secse_texts_sample.json", "secse")

    # Step 4: Verify E2E scenarios
    print("\n[4/4] Verifying E2E attack scenarios...")
    e2e_file = DATA_DIR / "e2e_attack_scenarios.json"
    if e2e_file.exists():
        with open(e2e_file) as f:
            scenarios = json.load(f)
        print(f"  ✓ {len(scenarios)} attack scenarios loaded")
    else:
        print("  ✗ e2e_attack_scenarios.json missing!")

    print("\n" + "=" * 60)
    print("SETUP COMPLETE")
    print("=" * 60)
    print("\nReady to run experiments:")
    print("  python exp1_fever_large_scale.py")
    print("  python exp2_multimodel_e2e.py")
    print("  python exp3_joint_hybrid_attack.py")


if __name__ == "__main__":
    main()
