"""Script to inject honeytokens into repository"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.injection_engine import InjectionEngine

def main():
    parser = argparse.ArgumentParser(description='Inject honeytokens into code repository')
    parser.add_argument('--repo', type=str, default='.', help='Repository path')
    parser.add_argument('--types', nargs='+', 
                       choices=['aws', 'db_postgresql', 'db_mysql', 'api', 'ssh'],
                       default=['aws'], help='Token types to inject')
    parser.add_argument('--files-per-type', type=int, default=5, 
                       help='Number of files per token type')
    parser.add_argument('--tokens-per-file', type=int, default=1,
                       help='Number of tokens per file')
    
    args = parser.parse_args()
    
    print(f"Injecting honeytokens into {args.repo}...")
    engine = InjectionEngine(Path(args.repo))
    
    results = engine.inject_into_repository(
        args.types,
        args.files_per_type,
        args.tokens_per_file
    )
    
    print(f"\n[SUCCESS] Injection complete!")
    print(f"  Files scanned: {results['total_files_scanned']}")
    print(f"  Files injected: {results['files_injected']}")
    print(f"  Tokens injected: {results['tokens_injected']}")

    if results['injections']:
        print("\nInjection locations:")
        for inj in results['injections'][:10]:  # Show first 10
            print(f"  - {inj['file']}:{inj['line']} ({inj['token_type']})")

if __name__ == "__main__":
    main()

