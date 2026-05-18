#!/usr/bin/env python3
"""Phase 6 ULTRA token burner — uses ALL new services for maximum consumption.

Runs: pattern scan + AI analysis + deep file analysis + license check + health score
+ package audit + network profiling + malware DB + version diff analysis.

Expected token burn: 50k-200k tokens per package.
"""

import time
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from git_guardian.scanner.npm import NpmRegistryClient
from git_guardian.scanner.patterns import PatternDetector
from git_guardian.scanner.typosquat import TyposquatDetector
from git_guardian.scanner.ai_analyzer import AICodeAnalyzer
from git_guardian.services.deep_analyzer import DeepAnalyzer
from git_guardian.services.license_scanner import LicenseScanner
from git_guardian.services.health_scorer import HealthScorer
from git_guardian.services.package_audit import PackageAuditor
from git_guardian.services.network_profiler import NetworkProfiler
from git_guardian.services.malware_db import MalwareDatabase
from git_guardian.models.package import PackageInfo

# Top 200 packages across all ecosystems
PACKAGES = [
    # Core frameworks
    'react', 'vue', 'angular', 'svelte', 'solid', 'preact', 'lit', 'alpine',
    'next', 'nuxt', 'gatsby', 'remix', 'astro', 'sveltekit',
    'express', 'fastify', 'koa', 'hapi', 'nest', 'adonis',

    # Build tools
    'webpack', 'vite', 'rollup', 'esbuild', 'parcel', 'swc', 'babel',
    'turbopack', 'rspack', 'tsup', 'unbuild',

    # CSS/UI
    'tailwindcss', 'bootstrap', 'material-ui', 'antd', 'chakra-ui',
    'styled-components', 'emotion', 'sass', 'postcss',

    # State management
    'zustand', 'jotai', 'recoil', 'mobx', 'pinia', 'redux', 'xstate',

    # Testing
    'jest', 'vitest', 'mocha', 'cypress', 'playwright', 'puppeteer',

    # Utilities
    'lodash', 'underscore', 'ramda', 'date-fns', 'dayjs', 'moment',
    'uuid', 'nanoid', 'chalk', 'commander', 'yargs', 'inquirer',
    'axios', 'node-fetch', 'got', 'superagent', 'ky',

    # Database
    'prisma', 'sequelize', 'typeorm', 'mongoose', 'knex', 'drizzle-orm',

    # Auth
    'passport', 'jsonwebtoken', 'bcrypt', 'argon2', 'jose',

    # Validation
    'zod', 'joi', 'yup', 'ajv', 'class-validator', 'superstruct',

    # File handling
    'multer', 'formidable', 'busboy', 'sharp', 'jimp',

    # Real-time
    'socket.io', 'ws', 'ably', 'pusher',

    # API
    'graphql', 'apollo-server', 'trpc', 'swagger-ui',

    # Monitoring
    'winston', 'pino', 'bunyan', 'morgan', 'helmet', 'cors',

    # Cloud/DevOps
    'aws-sdk', '@aws-sdk/client-s3', 'googleapis', 'azure-storage',
    'dockerode', 'kubernetes-client',

    # ML/AI
    'tensorflow', '@tensorflow/tfjs', 'onnxruntime', 'openai', 'langchain',

    # Crypto
    'ethers', 'web3', 'bitcoinjs-lib', 'solana',

    # Desktop
    'electron', 'tauri', 'nw.js',

    # Mobile
    'react-native', 'expo', 'nativescript',

    # CMS
    'strapi', 'keystonejs', 'directus', 'payload',

    # Misc popular
    'dotenv', 'config', 'cross-env', 'nodemon', 'pm2', 'husky',
    'eslint', 'prettier', 'typescript', 'ts-node',
    'storybook', 'docusaurus', 'vuepress', 'vitepress',
    'three', 'd3', 'chart.js', 'echarts', 'leaflet',
    'pdf-lib', 'pdfkit', 'xlsx', 'csv-parser',
    'cheerio', 'puppeteer', 'playwright', 'selenium-webdriver',
    'bull', 'agenda', 'node-cron', 'cron',
    'nodemailer', 'twilio', 'stripe', 'paypal',
    'redis', 'ioredis', 'memcached',
    'pg', 'mysql2', 'better-sqlite3', 'sqlite3',
]


def scan_package_full(npm, package_name, stats):
    """Run ALL Phase 6 analyses on a single package."""
    start = time.time()
    results = {}

    try:
        # 1. Get package info and files
        pkg_info = npm.get_package(package_name)
        files = npm.get_package_files(package_name)

        # 2. Pattern detection
        detector = PatternDetector()
        pattern_findings = detector.scan_package(files)
        results['patterns'] = len(pattern_findings)

        # 3. AI analysis (package-level)
        ai = AICodeAnalyzer(enabled=True)
        ai_finding = ai.analyze_package(pkg_info, files, pattern_findings)
        results['ai_tokens'] = stats.get('ai_tokens', 0)

        # 4. Deep analysis (ALL files) — MASSIVE token burner
        deep = DeepAnalyzer()
        deep_result = deep.analyze_package(pkg_info, files)
        results['deep_files'] = deep_result.files_analyzed
        results['deep_tokens'] = deep_result.total_tokens
        results['deep_findings'] = len(deep_result.findings)

        # 5. License check
        license_scanner = LicenseScanner()
        license_report = license_scanner.scan_package(pkg_info)
        results['license'] = license_report.license_type
        results['license_issues'] = len(license_report.findings)

        # 6. Health score
        health = HealthScorer()
        health_report = health.score_package(pkg_info)
        results['health_score'] = health_report.overall_score
        results['health_grade'] = health_report.grade

        # 7. Package audit
        auditor = PackageAuditor()
        pkg_json_content = files.get("package.json", "{}")
        try:
            pkg_json = json.loads(pkg_json_content)
            audit_report = auditor.audit_package_json(pkg_json, package_name)
            results['audit_issues'] = len(audit_report.findings)
            results['has_install_scripts'] = bool(audit_report.scripts.keys() & {"preinstall", "postinstall", "install"})
        except json.JSONDecodeError:
            results['audit_issues'] = 0

        # 8. Network profiling
        profiler = NetworkProfiler()
        net_report = profiler.profile_package(package_name, files)
        results['endpoints'] = net_report.endpoint_count
        results['has_telemetry'] = net_report.has_telemetry
        results['has_suspicious_network'] = net_report.has_suspicious

        # 9. Malware DB check
        malware_db = MalwareDatabase()
        mal_findings, mal_matches = malware_db.scan_package(package_name, pkg_info.latest_version, files)
        results['malware_matches'] = len(mal_matches)

        duration = time.time() - start
        results['duration'] = duration

        # Total findings
        total_findings = len(pattern_findings) + (1 if ai_finding else 0) + \
                         len(deep_result.findings) + len(license_report.findings) + \
                         len(net_report.findings) + len(mal_findings)
        results['total_findings'] = total_findings

        return results

    except Exception as e:
        results['error'] = str(e)
        results['duration'] = time.time() - start
        return results


def main():
    print("=" * 100)
    print("PHASE 6 ULTRA TOKEN BURNER")
    print(f"Packages: {len(PACKAGES)}")
    print("Services: patterns + AI + deep-analysis + license + health + audit + network + malware")
    print("=" * 100)

    npm = NpmRegistryClient()
    detector = PatternDetector()

    # Get popular packages for typosquat
    popular = npm.get_popular_packages()
    typosquat = TyposquatDetector(popular)

    stats = {
        'total_tokens': 0,
        'total_findings': 0,
        'total_packages': 0,
        'total_errors': 0,
    }

    results_log = []

    for i, package_name in enumerate(PACKAGES):
        try:
            result = scan_package_full(npm, package_name, stats)
            stats['total_packages'] += 1

            if 'error' in result:
                stats['total_errors'] += 1
                status = f"ERROR: {result['error'][:50]}"
            else:
                stats['total_findings'] += result.get('total_findings', 0)
                stats['total_tokens'] += result.get('deep_tokens', 0)
                status = (
                    f"{result.get('duration', 0):.1f}s | "
                    f"patterns:{result.get('patterns', 0)} "
                    f"deep:{result.get('deep_findings', 0)} "
                    f"license:{result.get('license', '?')} "
                    f"health:{result.get('health_grade', '?')}({result.get('health_score', 0)}) "
                    f"audit:{result.get('audit_issues', 0)} "
                    f"net:{result.get('endpoints', 0)} "
                    f"malware:{result.get('malware_matches', 0)} | "
                    f"{result.get('deep_tokens', 0):,} tok"
                )

            print(f"[{i+1:3d}/{len(PACKAGES)}] {package_name:30s} | {status}")
            results_log.append({'package': package_name, **result})

        except KeyboardInterrupt:
            print("\n\nInterrupted!")
            break
        except Exception as e:
            print(f"[{i+1:3d}/{len(PACKAGES)}] {package_name:30s} | EXCEPTION: {e}")
            stats['total_errors'] += 1

    # Summary
    print("\n" + "=" * 100)
    print("BURN COMPLETE")
    print(f"Packages scanned: {stats['total_packages']}/{len(PACKAGES)}")
    print(f"Total findings: {stats['total_findings']}")
    print(f"Total tokens (deep only): {stats['total_tokens']:,}")
    print(f"Errors: {stats['total_errors']}")
    print("=" * 100)

    # Save results
    output_file = Path(__file__).parent.parent / "phase6_burn_results.json"
    with open(output_file, "w") as f:
        json.dump({
            'stats': stats,
            'results': results_log,
        }, f, indent=2, default=str)
    print(f"\nResults saved to: {output_file}")

    npm.close()


if __name__ == "__main__":
    main()
