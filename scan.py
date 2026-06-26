#!/usr/bin/env python3
"""
vuln-scanner-agent — CLI entrypoint
Usage:
    python scan.py --repo https://github.com/user/repo
    python scan.py --image nginx:latest
    python scan.py --repo https://github.com/user/repo --image myapp:latest
"""

import argparse
import asyncio
import sys
from core.orchestrator import Orchestrator
from dotenv import load_dotenv

load_dotenv()

def parse_args():
    parser = argparse.ArgumentParser(
        description="Multi-agent vulnerability scanner for GitHub repos and Docker images"
    )
    parser.add_argument("--repo", type=str, help="GitHub repository URL")
    parser.add_argument("--image", type=str, help="Docker image (e.g. nginx:latest)")
    parser.add_argument("--url", type=str, help="Web application URL (e.g. https://example.com)")
    parser.add_argument("--output", type=str, default="report.md", help="Output report path")
    parser.add_argument("--issue", action="store_true", help="Create GitHub issue with findings")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM triage (faster, cheaper)")
    parser.add_argument("--pentest", action="store_true", help="Autonomous pentest mode (DeepSeek R1 ReAct loop)")
    return parser.parse_args()


async def main():
    args = parse_args()

    if not args.repo and not args.image and not args.url:
        print("Error: provide at least --repo, --image, or --url")
        sys.exit(1)

    orchestrator = Orchestrator(
        repo_url=args.repo,
        image=args.image,
        url=args.url,
        output_path=args.output,
        create_issue=args.issue,
        use_llm=not args.no_llm,
        pentest=args.pentest,
    )

    await orchestrator.run()


if __name__ == "__main__":
    asyncio.run(main())
