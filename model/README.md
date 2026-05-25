# Tron Model — Training Pipeline

This directory contains everything needed to build, train, and evaluate the `tron-model` —
a Gemma 4-based language model fine-tuned specifically for system security analysis.

## Architecture decision

| Option | Model | Size (Q4) | Use case |
|---|---|---|---|
| **tron-model-e2b** | gemma4-e2b fine-tuned | ~3 GB | Any hardware, fast inference |
| **tron-model-e4b** | gemma4-e4b fine-tuned | ~5 GB | Better reasoning, 16GB+ RAM recommended |

Start with **e2b** — it fits on any modern machine and security analysis is structured reasoning
(not open-ended creativity), where the smaller model performs close to parity.

## Directory layout

```
model/
├── ollama/
│   └── Modelfile.tron          ← Deploy today (specialized system prompt on e2b-turbo)
├── preprocessing/
│   ├── snapshot_to_prompt.py   ← Convert Tron SystemSnapshot JSON → training examples
│   ├── normalize_evtx.py       ← Parse Windows EVTX event logs → training examples
│   └── generate_analyses.py    ← LLM-assisted label generation for unlabeled snapshots
├── training/
│   ├── finetune.py             ← Unsloth LoRA fine-tuning (runs on any CUDA GPU)
│   └── export_gguf.py          ← Merge LoRA → BF16 → IQ4_XS GGUF for Ollama
├── eval/
│   └── eval.py                 ← Evaluate against held-out test set
├── datasets/
│   ├── README.md               ← Dataset format documentation
│   ├── security_events.jsonl   ← Event log training pairs (build with normalize_evtx.py)
│   ├── telemetry_snapshots.jsonl ← Snapshot analysis pairs (build with snapshot_to_prompt.py)
│   └── process_profiles.jsonl  ← Process behaviour profiles
└── requirements.txt            ← Python dependencies
```

## Quick start: Deploy today (no training required)

The `Modelfile.tron` uses the existing `gemma4-e2b-iq4xs-turbo.gguf` with a specialized
security system prompt. No training needed — deploy in 30 seconds:

```bash
ollama create tron-model -f model/ollama/Modelfile.tron
```

Then update `appsettings.json`:
```json
"Ai": {
  "EndpointUrl": "http://localhost:11434",
  "Model": "tron-model"
}
```

## Fine-tuning pipeline (Phase 2)

### 1. Install dependencies
```bash
cd model
pip install -r requirements.txt
```

### 2. Generate training data from live Tron output
```bash
# Collect snapshots from a running Tron instance:
python preprocessing/snapshot_to_prompt.py \
  --input /path/to/tron-snapshots.jsonl \
  --output datasets/telemetry_snapshots.jsonl

# Parse public EVTX attack samples:
python preprocessing/normalize_evtx.py \
  --input /path/to/evtx-attack-samples/ \
  --output datasets/security_events.jsonl

# Generate analysis labels using a capable model (GPT-4o, Gemini 1.5 Pro, etc.):
python preprocessing/generate_analyses.py \
  --input datasets/telemetry_snapshots.jsonl \
  --model gemini-2.5-pro \
  --output datasets/telemetry_snapshots_labeled.jsonl
```

### 3. Fine-tune
```bash
# Requires CUDA GPU (12GB+ VRAM for e2b, 24GB+ for e4b)
# On CPU-only: use the Modelfile.tron approach instead
python training/finetune.py \
  --base-model google/gemma-4-e2b-it \
  --datasets datasets/security_events.jsonl datasets/telemetry_snapshots_labeled.jsonl \
  --output-dir ./tron-lora \
  --epochs 3
```

### 4. Export to GGUF
```bash
python training/export_gguf.py \
  --lora-dir ./tron-lora \
  --base-model google/gemma-4-e2b-it \
  --quantize IQ4_XS \
  --output tron-model-v1.gguf
```

### 5. Deploy
```bash
# Copy to gemma4 family directory, create Ollama model:
ollama create tron-model-v1 -f model/ollama/Modelfile.tron
# Update Modelfile FROM to point at tron-model-v1.gguf
```

## Dataset sources

| Dataset | Source | Size target | Script |
|---|---|---|---|
| Security event logs | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), DARPA TCDE | 50K events | `normalize_evtx.py` |
| Telemetry snapshots | Live Tron output on your system | 5K–10K pairs | `snapshot_to_prompt.py` |
| Process profiles | Sysmon captures, [LOLBins](https://lolbas-project.github.io/) | 5K profiles | Built into `normalize_evtx.py` |
| MITRE ATT&CK NLP | [ATT&CK STIX data](https://github.com/mitre/cti) | 14K techniques | `generate_analyses.py` |

All data stays local. No telemetry leaves your machine.

## Integration with Tron

The trained model plugs directly into the existing `LocalModelAnalyzer`:

```json
"Ai": {
  "EndpointUrl": "http://localhost:11434",
  "Model": "tron-model-v1"
}
```

No code changes required — just swap the model name.
