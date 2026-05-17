#!/usr/bin/env python3
"""Dependency tree scanner - scans transitive deps of popular packages."""

import time
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from git_guardian.services.dependency_scanner import DependencyScanner

# Popular packages with deep dependency trees
PACKAGES = [
    'express', 'react', 'vue', 'angular', 'next', 'nuxt',
    'webpack', 'vite', 'babel', 'eslint', 'prettier',
    'jest', 'mocha', 'chai', 'cypress', 'playwright',
    'axios', 'got', 'node-fetch', 'undici',
    'lodash', 'moment', 'date-fns', 'dayjs',
    'mongoose', 'sequelize', 'typeorm', 'prisma',
    'socket.io', 'ws', 'graphql', 'apollo-server',
    'passport', 'jsonwebtoken', 'bcrypt',
    'multer', 'sharp', 'canvas',
    'nodemailer', 'sendgrid', 'twilio',
    'stripe', 'paypal', 'braintree',
    'aws-sdk', 'googleapis', 'azure',
    'pm2', 'nodemon', 'husky',
    'storybook', 'typedoc', 'jsdoc',
    'tailwindcss', 'bootstrap', 'material-ui',
    'redux', 'mobx', 'zustand', 'jotai',
    'd3', 'chart.js', 'recharts', 'plotly.js',
    'three.js', 'phaser', 'pixi.js',
    'electron', 'tauri', 'react-native', 'expo',
]


def main():
    total_packages = 0
    total_findings = 0
    total_tokens = 0
    results = []

    print('DEPENDENCY TREE SCANNER')
    print(f'Packages to scan: {len(PACKAGES)}')
    print('=' * 80)

    start_time = time.time()

    for pkg_name in PACKAGES:
        try:
            with DependencyScanner(max_depth=3, max_packages=30) as scanner:
                result = scanner.scan_dependencies(pkg_name)

            total_packages += result.total_packages
            total_findings += result.total_findings
            # Estimate tokens: ~500 per package + findings
            pkg_tokens = result.total_packages * 500 + result.total_findings * 200
            total_tokens += pkg_tokens

            elapsed = time.time() - start_time
            rate = total_tokens / elapsed if elapsed > 0 else 0

            findings_str = f'{result.total_findings} findings' if result.total_findings > 0 else 'SAFE'
            print(f'  {pkg_name:25s} | {result.total_packages:3d} deps | {result.total_findings:3d} findings | {pkg_tokens:>8,} tok | {rate:,.0f} tok/s')

            results.append({
                'package': pkg_name,
                'deps': result.total_packages,
                'findings': result.total_findings,
                'tokens': pkg_tokens,
                'duration': result.scan_duration_seconds,
            })

        except Exception as e:
            print(f'  [ERR] {pkg_name:25s} | {str(e)[:60]}')

    elapsed = time.time() - start_time
    print('=' * 80)
    print('DEPENDENCY SCAN REPORT:')
    print(f'  Duration: {elapsed:.0f}s ({elapsed/60:.1f} min)')
    print(f'  Packages scanned: {len(PACKAGES)}')
    print(f'  Total dependencies: {total_packages}')
    print(f'  Total findings: {total_findings}')
    print(f'  TOTAL TOKENS BURNED: {total_tokens:,}')
    print(f'  Rate: {total_tokens/elapsed:,.0f} tokens/second')

    with open('dep_scan_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f'  Results saved to dep_scan_results.json')


if __name__ == '__main__':
    main()
