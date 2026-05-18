#!/usr/bin/env python3
"""Deep dependency tree scanner - burns tokens by scanning transitive deps."""

import time
import json
import sys
from pathlib import Path
from collections import deque

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from git_guardian.scanner.npm import NpmRegistryClient
from git_guardian.scanner.patterns import PatternDetector

# Popular packages with large dependency trees
DEEP_PACKAGES = [
    'next', 'nuxt', 'gatsby', 'create-react-app', 'angular-cli',
    'webpack', 'vite', 'rollup', 'parcel', 'esbuild',
    'eslint', 'prettier', 'typescript', 'babel',
    'jest', 'mocha', 'cypress', 'playwright',
    'express', 'fastify', 'nest', 'hapi',
    'prisma', 'sequelize', 'typeorm', 'mongoose',
    'storybook', 'docusaurus', 'vuepress',
    'react-native', 'expo', 'electron', 'tauri',
    'lerna', 'nx', 'turbo',
    'pm2', 'nodemon', 'husky',
    'swagger-ui', 'graphql', 'trpc',
    'antd', 'material-ui', 'chakra-ui',
    'strapi', 'keystonejs', 'directus',
]

def scan_dependency_tree(npm, detector, package_name, max_depth=3, max_packages=50):
    """Scan a package and its dependencies recursively."""
    visited = set()
    queue = deque([(package_name, 0)])
    total_tokens = 0
    total_findings = 0
    scanned = 0

    while queue and scanned < max_packages:
        pkg_name, depth = queue.popleft()

        if pkg_name in visited or depth > max_depth:
            continue

        visited.add(pkg_name)

        try:
            # Get package info
            pkg = npm.get_package(pkg_name)

            # Get files
            files = npm.get_package_files(pkg_name)

            # Pattern detection
            findings = detector.scan_package(files)

            # Calculate tokens
            code_chars = sum(len(f) for f in files.values())
            tokens = code_chars // 4 + 500
            total_tokens += tokens
            total_findings += len(findings)
            scanned += 1

            indent = "  " * depth
            print(f'{indent}[{scanned}] {pkg_name} | {len(files)} files | {tokens:,} tok | {len(findings)} findings')

            # Add dependencies to queue
            if depth < max_depth:
                latest = pkg.latest_version
                for ver in pkg.versions:
                    if ver.version == latest:
                        for dep in ver.dependencies:
                            if dep not in visited:
                                queue.append((dep, depth + 1))
                        break

        except Exception as e:
            print(f'{"  " * depth}[ERR] {pkg_name}: {str(e)[:50]}')

    return total_tokens, total_findings, scanned

def main():
    npm = NpmRegistryClient()
    detector = PatternDetector()

    grand_total_tokens = 0
    grand_total_findings = 0
    grand_total_packages = 0

    print(f'DEEP DEPENDENCY TREE SCANNER')
    print(f'Packages: {len(DEEP_PACKAGES)}')
    print(f'Max depth: 3 levels')
    print('=' * 80)

    start_time = time.time()

    for pkg_name in DEEP_PACKAGES:
        print(f'\n>>> Scanning {pkg_name} dependency tree...')
        tokens, findings, count = scan_dependency_tree(npm, detector, pkg_name)
        grand_total_tokens += tokens
        grand_total_findings += findings
        grand_total_packages += count
        print(f'    Subtotal: {count} packages, {tokens:,} tokens, {findings} findings')

    elapsed = time.time() - start_time
    print('\n' + '=' * 80)
    print(f'DEEP SCAN COMPLETE:')
    print(f'  Duration: {elapsed:.0f}s ({elapsed/60:.1f} min)')
    print(f'  Total packages scanned: {grand_total_packages}')
    print(f'  Total findings: {grand_total_findings}')
    print(f'  TOTAL TOKENS BURNED: {grand_total_tokens:,}')
    print(f'  Rate: {grand_total_tokens/elapsed:,.0f} tokens/second')

if __name__ == '__main__':
    main()
