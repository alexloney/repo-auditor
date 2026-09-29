import argparse
import importlib
import sys
from pathlib import Path

def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Audit a code repository.")
    parser.add_argument("repo_path", nargs="?", help="Target repository directory")
    parser.add_argument("--scans", type=str, default="all", help="Comma-separated list of scanners. Default: all")
    parser.add_argument("--list", action="store_true", help="List available scan plugins and exit")
    parser.add_argument("--model", type=str, help="Specify the LLM model to use for scanning. Default: qwen-coder-64k:latest", default="qwen-coder-64k:latest")
    parser.add_argument("--ollama", type=str, help="Specify the Ollama host to use for scanning. Default: localhost:11434", default="localhost:11434")
    
    parsed = parser.parse_args(args)

    if not parsed.repo_path and not parsed.list:
        parser.print_help()
        sys.exit(1)

    return parsed

def main(args=None):
    parsed_args = parse_args(args)

    # TODO: Implement

    return 0