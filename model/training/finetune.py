#!/usr/bin/env python3
"""
finetune.py — Fine-tune Gemma 4 E4B on Tron security datasets using Unsloth LoRA.

Requirements:
  - CUDA GPU: 24GB+ VRAM for e4b (use e2b with --base-model google/gemma-4-e2b-it for 12GB)
  - pip install -r requirements.txt

Usage:
    # Fine-tune e4b (default — best reasoning for security analysis):
    python finetune.py \\
        --base-model google/gemma-4-e4b-it \\
        --datasets datasets/security_events_labeled.jsonl datasets/telemetry_snapshots_labeled.jsonl \\
        --output-dir ./tron-lora-e4b \\
        --epochs 3

    # Fine-tune e2b (lower VRAM alternative, 12GB+):
    python finetune.py \\
        --base-model google/gemma-4-e2b-it \\
        --datasets datasets/security_events_labeled.jsonl datasets/telemetry_snapshots_labeled.jsonl \\
        --output-dir ./tron-lora-e2b \\
        --epochs 3 \\
        --lora-rank 16

After training, run export_gguf.py to merge and quantize for Ollama.
"""

import argparse
import json
import sys
from pathlib import Path


def load_datasets(dataset_paths: list[Path]) -> list[dict]:
    examples = []
    for path in dataset_paths:
        if not path.exists():
            print(f"  ⚠ Dataset not found: {path}", file=sys.stderr)
            continue
        before = len(examples)
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                # Skip unlabeled examples
                msgs = rec.get("messages", [])
                if any(m["content"] == "[NEEDS_LABEL]" for m in msgs):
                    continue
                examples.append(rec)
        print(f"  Loaded {len(examples) - before} labeled examples from {path.name}")
    return examples


def format_chat(example: dict, tokenizer) -> str:
    """Apply the Gemma 4 chat template to a training example."""
    return tokenizer.apply_chat_template(
        example["messages"],
        tokenize=False,
        add_generation_prompt=False
    )


def main():
    parser = argparse.ArgumentParser(description="Fine-tune tron-model with Unsloth LoRA")
    parser.add_argument("--base-model",  default="google/gemma-4-e4b-it",
                        help="HuggingFace model ID (or local path)")
    parser.add_argument("--datasets",    nargs="+", required=True, type=Path,
                        help="Labeled JSONL training datasets")
    parser.add_argument("--output-dir",  default="./tron-lora", type=Path,
                        help="Directory to save LoRA adapter")
    parser.add_argument("--epochs",      type=int,   default=3,    help="Training epochs")
    parser.add_argument("--lora-rank",   type=int,   default=32,   help="LoRA rank (32 for e4b)")
    parser.add_argument("--lora-alpha",  type=int,   default=32,   help="LoRA alpha")
    parser.add_argument("--lr",          type=float, default=2e-4, help="Learning rate")
    parser.add_argument("--batch-size",  type=int,   default=4,    help="Per-device batch size")
    parser.add_argument("--grad-accum",  type=int,   default=8,    help="Gradient accumulation steps")
    parser.add_argument("--max-seq-len", type=int,   default=4096, help="Max sequence length")
    parser.add_argument("--eval-split",  type=float, default=0.05, help="Fraction held out for eval")
    parser.add_argument("--save-steps",  type=int,   default=100,  help="Save checkpoint every N steps")
    args = parser.parse_args()

    # --- Import checks ---
    try:
        from unsloth import FastLanguageModel
    except ImportError:
        print("Error: unsloth not installed. Run: pip install unsloth", file=sys.stderr)
        print("  See: https://github.com/unslothai/unsloth", file=sys.stderr)
        sys.exit(1)

    try:
        from trl import SFTTrainer, SFTConfig
        from datasets import Dataset
    except ImportError:
        print("Error: trl or datasets not installed. Run: pip install trl datasets", file=sys.stderr)
        sys.exit(1)

    # --- Load base model ---
    print(f"\n[1/5] Loading base model: {args.base_model}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name    = args.base_model,
        max_seq_length = args.max_seq_len,
        load_in_4bit  = True,   # QLoRA — reduces VRAM usage
        dtype         = None,   # auto-detect
    )

    # --- Add LoRA adapters ---
    print(f"[2/5] Adding LoRA adapters (rank={args.lora_rank})")
    model = FastLanguageModel.get_peft_model(
        model,
        r              = args.lora_rank,
        lora_alpha     = args.lora_alpha,
        target_modules = ["q_proj", "k_proj", "v_proj", "o_proj",
                          "gate_proj", "up_proj", "down_proj"],
        lora_dropout   = 0.05,
        bias           = "none",
        use_gradient_checkpointing = "unsloth",
        random_state   = 42,
    )

    # --- Load datasets ---
    print(f"[3/5] Loading training data")
    examples = load_datasets(args.datasets)
    if not examples:
        print("Error: no labeled examples found. Run generate_analyses.py first.", file=sys.stderr)
        sys.exit(1)

    print(f"  Total: {len(examples)} labeled examples")

    # Format with chat template
    texts = [format_chat(ex, tokenizer) for ex in examples]

    # Train/eval split
    split_idx = int(len(texts) * (1 - args.eval_split))
    train_texts = texts[:split_idx]
    eval_texts  = texts[split_idx:]
    print(f"  Train: {len(train_texts)}, Eval: {len(eval_texts)}")

    train_dataset = Dataset.from_dict({"text": train_texts})
    eval_dataset  = Dataset.from_dict({"text": eval_texts})

    # --- Train ---
    print(f"[4/5] Training ({args.epochs} epochs, lr={args.lr})")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    trainer = SFTTrainer(
        model     = model,
        tokenizer = tokenizer,
        train_dataset = train_dataset,
        eval_dataset  = eval_dataset,
        dataset_text_field = "text",
        max_seq_length = args.max_seq_len,
        args = SFTConfig(
            output_dir              = str(args.output_dir),
            num_train_epochs        = args.epochs,
            per_device_train_batch_size = args.batch_size,
            gradient_accumulation_steps = args.grad_accum,
            learning_rate           = args.lr,
            lr_scheduler_type       = "cosine",
            warmup_ratio            = 0.05,
            fp16                    = True,
            logging_steps           = 10,
            evaluation_strategy     = "steps",
            eval_steps              = args.save_steps,
            save_steps              = args.save_steps,
            save_total_limit        = 3,
            load_best_model_at_end  = True,
            metric_for_best_model   = "eval_loss",
            report_to               = "none",
            seed                    = 42,
            dataset_num_proc        = 4,
        )
    )

    trainer_stats = trainer.train()
    print(f"  Training complete: {trainer_stats.metrics}")

    # --- Save LoRA adapter ---
    print(f"[5/5] Saving LoRA adapter to {args.output_dir}")
    model.save_pretrained(str(args.output_dir))
    tokenizer.save_pretrained(str(args.output_dir))

    print(f"\n✓ Done! LoRA adapter saved to {args.output_dir}")
    print(f"  Next: run export_gguf.py --lora-dir {args.output_dir} to build tron-model.gguf")


if __name__ == "__main__":
    main()
