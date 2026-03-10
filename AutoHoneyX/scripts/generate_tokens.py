"""Script to generate honeytokens"""

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.honeytoken_generator import HoneytokenGenerator

def main():
    parser = argparse.ArgumentParser(description='Generate honeytokens')
    parser.add_argument('--type', choices=['aws', 'db_postgresql', 'db_mysql', 'api', 'ssh'],
                       default='aws', help='Token type to generate')
    parser.add_argument('--count', type=int, default=1, help='Number of tokens to generate')
    parser.add_argument('--output', type=str, help='Output file path')
    
    args = parser.parse_args()
    
    tokens = []
    for i in range(args.count):
        if args.type == 'aws':
            token_data = HoneytokenGenerator.generate_aws_key()
        elif args.type.startswith('db_'):
            db_type = args.type.replace('db_', '')
            token_data = HoneytokenGenerator.generate_database_credentials(db_type)
        elif args.type == 'api':
            token_data = HoneytokenGenerator.generate_api_key()
        elif args.type == 'ssh':
            token_data = HoneytokenGenerator.generate_ssh_key()
        
        honeytoken = HoneytokenGenerator.save_honeytoken(token_data)
        tokens.append((honeytoken.token_id, token_data['token_value']))
        print(f"Generated token {i+1}/{args.count}: {honeytoken.token_id}")
    
    if args.output:
        with open(args.output, 'w') as f:
            for token_id, token_value in tokens:
                f.write(f"# Token ID: {token_id}\n")
                f.write(f"{token_value}\n\n")
        print(f"Tokens written to {args.output}")

if __name__ == "__main__":
    main()

