#!/usr/bin/env python3
"""CLI interface and argument parsing for Recon Pro."""

import argparse
import sys
from pathlib import Path

from .core.scanner import ReconScanner
from .utils import setup_logging


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Recon passivo de JS para bug bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s -u example.com
  %(prog)s -l dominios.txt --scope escopo.txt --threads 20
  %(prog)s -u example.com --validate-secrets --nuclei
        """,
    )

    # Targets
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", help="domínio ou URL único alvo")
    target_group.add_argument("-l", help="arquivo com lista de domínios (um por linha)")

    # Scope
    parser.add_argument(
        "--scope", help="arquivo com domínios em escopo (filtra subdomínios fora dele)"
    )

    # Performance
    parser.add_argument(
        "--threads", type=int, default=10, help="threads paralelas p/ análise de JS (default: 10)"
    )
    parser.add_argument(
        "--timeout", type=int, default=8, help="timeout por request em segundos (default: 8)"
    )
    parser.add_argument(
        "--retries", type=int, default=2, help="tentativas extra por request (default: 2)"
    )
    parser.add_argument(
        "--tool-timeout",
        type=int,
        default=600,
        help="timeout para execução em lote de ferramentas externas em segundos (default: 600)",
    )
    parser.add_argument(
        "--katana-concurrency",
        type=int,
        default=25,
        help="concorrência interna do katana (default: 25)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.0, help="delay entre requests por thread em segundos (default: 0.0)"
    )

    # Output
    parser.add_argument(
        "--output-dir", default="recon_pro_output", help="diretório base de saída (default: recon_pro_output)"
    )
    parser.add_argument(
        "--keep-old",
        action="store_true",
        help="não apaga pastas de execuções anteriores",
    )

    # Verification
    parser.add_argument(
        "--verify-endpoints",
        action="store_true",
        help="faz HEAD request pra confirmar existência real do endpoint",
    )
    parser.add_argument(
        "--verify-all",
        action="store_true",
        help="verifica TODOS os endpoints (inclusive MEDIUM)",
    )

    # Source maps
    parser.add_argument(
        "--skip-sourcemaps",
        action="store_true",
        help="desativa a checagem de source maps expostos",
    )

    # Validation
    parser.add_argument(
        "--validate-secrets",
        action="store_true",
        help="valida secrets contra APIs oficiais dos provedores (ativo)",
    )

    # Cache
    parser.add_argument(
        "--http-cache", action="store_true", help="ativa cache de requests em disco (requer requests-cache)"
    )

    # External tools
    parser.add_argument(
        "--nuclei",
        action="store_true",
        help="roda nuclei com templates exposed-panels ao final",
    )

    # Exposures
    parser.add_argument(
        "--skip-exposure-checks",
        action="store_true",
        help="desativa checagem de arquivos sensíveis bem conhecidos e CORS",
    )

    # Logging
    parser.add_argument("-v", "--verbose", action="store_true", help="log detalhado (DEBUG)")

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    # Setup logging
    logger = setup_logging(args.output_dir, args.verbose)
    logger.info("=== Recon Pro v2.0 iniciado ===")

    try:
        # Initialize and run scanner
        scanner = ReconScanner(args, logger)
        scanner.run()
        logger.info("=== Recon Pro finalizado com sucesso ===")
        return 0
    except KeyboardInterrupt:
        logger.warning("\nInterrompido pelo usuário")
        return 130
    except Exception as e:
        logger.error(f"Erro fatal: {e}", exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    sys.exit(main())
