#!/usr/bin/env python3
"""Main entry point for AutoHoneyX"""

import sys
# OLD_AWS_ACCESS_KEY_ID=AKIA7D5RJ3ECPMX8XBGD
# OLD_AWS_SECRET_ACCESS_KEY=AUEkiwk66irR33mYmgM0loFi4BsLDfWFxxx0FPnx
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='AutoHoneyX - Honeypot and Honeytoken Management')
    parser.add_argument('command', choices=['dashboard', 'monitor', 'generate', 'inject', 'init-db'],
                       help='Command to run')
    parser.add_argument('--type', help='Token type for generate command')
    parser.add_argument('--count', type=int, default=1, help='Number of tokens to generate')
    parser.add_argument('--repo', help='Repository path for inject command')
    
    args = parser.parse_args()
    
    if args.command == 'dashboard':
        os.system('streamlit run dashboard/app.py')
    elif args.command == 'monitor':
        from monitoring.monitor_service import MonitorService
        service = MonitorService()
        service.start()
    elif args.command == 'generate':
        from scripts.generate_tokens import main as generate_main
        sys.argv = ['generate_tokens.py', '--type', args.type or 'aws', '--count', str(args.count)]
        generate_main()
    elif args.command == 'inject':
        from scripts.inject_tokens import main as inject_main
        sys.argv = ['inject_tokens.py', '--repo', args.repo or '.']
        inject_main()
    elif args.command == 'init-db':
        from scripts.init_db import main as init_main
        init_main()

