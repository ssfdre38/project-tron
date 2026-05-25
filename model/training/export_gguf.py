#!/usr/bin/env python3
"""
export_gguf.py — Merge LoRA adapter into the base model, export to BF16, then quantize to IQ4_XS GGUF.

Uses:
  1. Unsloth to merge LoRA → full model (saved as safetensors)
  2. llama.cpp convert_hf_to_gguf.py to convert to BF16 GGUF
  3. llama-quantize to quantize to IQ4_XS (best quality/size tradeoff)

Requirements:
  - llama.cpp binaries at LLAMA_CPP_DIR (default: C:\Users\admin\gemma4-turbo-family\llama-cpp)
  - Python: unsloth, transformers

Usage:
    python export_gguf.py \\
        --lora-dir ./tron-lora-e2b \\
        --base-model google/gemma-4-e2b-it \\
        --output tron-model-e2b-v1.gguf

    # Then register with Ollama:
    # Copy Modelfile.tron and update the FROM line, then:
    # ollama create tron-model -f Modelfile.tron
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_LLAMA_CPP = Path(r"C:\Users\admin\gemma4-turbo-family\llama-cpp")


def find_convert_script(llama_cpp_dir: Path) -> Path | None:
    """Find convert_hf_to_gguf.py — shipped with llama.cpp source."""
    candidates = [
        llama_cpp_dir.parent / "convert_hf_to_gguf.py",
        llama_cpp_dir.parent / "llama.cpp" / "convert_hf_to_gguf.py",
        Path("convert_hf_to_gguf.py"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def merge_lora(lora_dir: Path, output_dir: Path):
    """Merge LoRA adapter into full BF16 model using Unsloth."""
    print(f"[1/3] Merging LoRA adapter from {lora_dir}")
    try:
        from unsloth import FastLanguageModel
    except ImportError:
        print("Error: unsloth not installed", file=sys.stderr)
        sys.exit(1)

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name    = str(lora_dir),
        load_in_4bit  = True,
    )
    print(f"  Saving merged model to {output_dir} ...")
    model.save_pretrained_merged(str(output_dir), tokenizer, save_method="merged_16bit")
    print(f"  ✓ Merged model saved")


def convert_to_gguf_bf16(model_dir: Path, gguf_bf16_path: Path, llama_cpp_dir: Path):
    """Convert HF safetensors → BF16 GGUF using llama.cpp."""
    print(f"[2/3] Converting to BF16 GGUF")

    convert_script = find_convert_script(llama_cpp_dir)
    if not convert_script:
        print("  ⚠ convert_hf_to_gguf.py not found.", file=sys.stderr)
        print("  Clone llama.cpp and place convert_hf_to_gguf.py next to the llama-cpp/ directory.", file=sys.stderr)
        print("  https://github.com/ggerganov/llama.cpp", file=sys.stderr)
        sys.exit(1)

    cmd = [
        sys.executable, str(convert_script),
        str(model_dir),
        "--outtype", "bf16",
        "--outfile", str(gguf_bf16_path),
    ]
    print(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        print("  ✗ Conversion failed", file=sys.stderr)
        sys.exit(1)
    print(f"  ✓ BF16 GGUF saved: {gguf_bf16_path}")


def quantize_gguf(bf16_path: Path, output_path: Path, quant_type: str, llama_cpp_dir: Path):
    """Quantize BF16 GGUF to target quantization type."""
    print(f"[3/3] Quantizing to {quant_type}")

    quantize_exe = llama_cpp_dir / "llama-quantize.exe"
    if not quantize_exe.exists():
        quantize_exe = llama_cpp_dir / "llama-quantize"
    if not quantize_exe.exists():
        print(f"  ✗ llama-quantize not found at {llama_cpp_dir}", file=sys.stderr)
        sys.exit(1)

    cmd = [str(quantize_exe), str(bf16_path), str(output_path), quant_type]
    print(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        print("  ✗ Quantization failed", file=sys.stderr)
        sys.exit(1)

    size_gb = output_path.stat().st_size / 1e9
    print(f"  ✓ {quant_type} GGUF saved: {output_path} ({size_gb:.2f} GB)")


def main():
    parser = argparse.ArgumentParser(description="Export tron LoRA to GGUF for Ollama")
    parser.add_argument("--lora-dir",    required=True, type=Path,
                        help="Directory containing trained LoRA adapter")
    parser.add_argument("--output",      required=True, type=Path,
                        help="Output GGUF file path (e.g. tron-model-v1.gguf)")
    parser.add_argument("--quantize",    default="IQ4_XS",
                        help="Quantization type (default: IQ4_XS). Options: Q4_K_M, Q5_K_M, IQ4_XS, Q3_K_S")
    parser.add_argument("--llama-cpp",   default=DEFAULT_LLAMA_CPP, type=Path,
                        help=f"Path to llama-cpp binaries (default: {DEFAULT_LLAMA_CPP})")
    parser.add_argument("--keep-bf16",   action="store_true",
                        help="Keep intermediate BF16 GGUF (deleted by default)")
    args = parser.parse_args()

    if not args.lora_dir.exists():
        print(f"Error: LoRA directory not found: {args.lora_dir}", file=sys.stderr)
        sys.exit(1)

    # Intermediate paths
    merged_dir  = args.lora_dir.parent / (args.lora_dir.name + "-merged")
    bf16_path   = args.output.with_suffix("").with_suffix(".bf16.gguf")

    # Step 1: Merge LoRA
    merge_lora(args.lora_dir, merged_dir)

    # Step 2: Convert to BF16 GGUF
    convert_to_gguf_bf16(merged_dir, bf16_path, args.llama_cpp)

    # Step 3: Quantize
    quantize_gguf(bf16_path, args.output, args.quantize, args.llama_cpp)

    # Cleanup
    if not args.keep_bf16 and bf16_path.exists():
        bf16_path.unlink()
        print(f"  Removed intermediate BF16 file")
    if merged_dir.exists():
        shutil.rmtree(merged_dir, ignore_errors=True)
        print(f"  Removed intermediate merged dir")

    print(f"\n✓ tron-model exported: {args.output}")
    print(f"\nNext steps:")
    print(f"  1. Update model/ollama/Modelfile.tron — change FROM to: {args.output}")
    print(f"  2. ollama create tron-model -f model/ollama/Modelfile.tron")
    print(f"  3. In appsettings.json: set Ai.Model = \"tron-model\"")


if __name__ == "__main__":
    main()
