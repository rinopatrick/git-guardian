#!/usr/bin/env python3
"""Batch API scanner - scans packages through the API to burn tokens."""

import time
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from git_guardian.scanner.npm import NpmRegistryClient
from git_guardian.scanner.patterns import PatternDetector
from git_guardian.scanner.typosquat import TyposquatDetector
from git_guardian.scanner.rate_limiter import get_npm_rate_limiter
from git_guardian.services.comparison_service import compare_scans
from git_guardian.services.export_service import ExportService

# Additional packages for batch scanning
PACKAGES = [
    # Security-focused packages
    'helmet', 'cors', 'csurf', 'express-rate-limit', 'express-validator',
    'joi', 'yup', 'zod', 'ajv', 'superstruct', 'io-ts', 'runtypes',
    'class-validator', 'class-transformer', 'arktype', 'valibot',
    'bcrypt', 'argon2', 'scrypt', 'jsonwebtoken', 'jose',
    'passport', 'passport-jwt', 'passport-local', 'keycloak-js',
    'oauth2-server', 'openid-client', 'oidc-provider',

    # Data processing
    'csv-parse', 'csv-stringify', 'papaparse', 'fast-csv',
    'xlsx', 'docx', 'pdf-lib', 'pdfkit', 'puppeteer',
    'sharp', 'jimp', 'canvas', 'imagemagick',
    'xml2js', 'fast-xml-parser', 'cheerio', 'jsdom',

    # Networking
    'axios', 'got', 'ky', 'superagent', 'node-fetch', 'undici',
    'ws', 'socket.io', 'sockjs', 'faye-websocket',
    'graphql', 'apollo-server', 'type-graphql', 'graphql-yoga',
    'trpc', 'grpc', 'json-rpc-2.0',

    # Database
    'prisma', 'drizzle', 'kysely', 'knex', 'sequelize', 'typeorm',
    'mongoose', 'mongodb', 'redis', 'ioredis', 'pg', 'mysql2',
    'better-sqlite3', 'sql.js', 'nedb', 'lowdb',

    # State management
    'zustand', 'jotai', 'recoil', 'mobx', 'pinia', 'vuex', 'redux',
    'xstate', 'valtio', 'nanostores', 'legend-state', 'effector',

    # Build tools
    'webpack', 'vite', 'rollup', 'esbuild', 'parcel', 'swc', 'babel',
    'rspack', 'farm', 'turbopack', 'tsup', 'unbuild',

    # Testing
    'jest', 'vitest', 'mocha', 'chai', 'jasmine', 'ava', 'tap',
    'cypress', 'playwright', 'testing-library', 'msw', 'nock', 'sinon',
    'puppeteer', 'selenium-webdriver', 'nightwatch', 'webdriverio',

    # CLI tools
    'yargs', 'commander', 'meow', 'oclif', 'clipanion',
    'ink', 'blessed', 'terminal-kit', 'inquirer', 'prompts',

    # Logging
    'winston', 'pino', 'bunyan', 'log4js', 'morgan',
    'consola', 'listr2', 'ora', 'signale',

    # Template engines
    'ejs', 'pug', 'handlebars', 'nunjucks', 'mustache', 'liquidjs', 'eta',

    # Utilities
    'date-fns', 'dayjs', 'luxon', 'moment',
    'uuid', 'nanoid', 'cuid', 'ulid',
    'glob', 'fast-glob', 'minimatch', 'micromatch',
    'chokidar', 'watchman', 'sane', 'onchange',
    'execa', 'shelljs', 'cross-spawn', 'zx',
    'chalk', 'kleur', 'picocolors', 'ansi-colors',
    'debug', 'dotenv', 'cross-env', 'config',

    # Web frameworks
    'fastify', 'hono', 'elysia', 'hapi', 'koa', 'express',
    'restify', 'loopback', 'feathers', 'nest', 'adonis',

    # Monitoring
    'prom-client', 'newrelic', 'sentry', 'bugsnag', 'rollbar',
    'datadog', 'opentelemetry',

    # Cloud
    'aws-sdk', 'googleapis', 'azure',
    '@aws-sdk/client-s3', '@aws-sdk/client-lambda',
    '@google-cloud/storage', '@azure/storage-blob',

    # Misc
    'dotenv', 'cross-env', 'shelljs', 'execa', 'zx',
    'fastify', 'hono', 'elysia', 'effect', 'trpc', 'hapi', 'koa', 'express',
]


def main():
    npm = NpmRegistryClient()
    detector = PatternDetector()
    typosquat = TyposquatDetector(npm.get_popular_packages())
    rate_limiter = get_npm_rate_limiter()

    total_tokens = 0
    scanned = 0
    findings_count = 0
    errors = 0
    all_findings = []

    unique_packages = list(set(PACKAGES))
    print('BATCH API SCANNER')
    print(f'Unique packages: {len(unique_packages)}')
    print('=' * 80)

    start_time = time.time()

    for pkg_name in unique_packages:
        try:
            rate_limiter.acquire()

            pkg = npm.get_package(pkg_name)
            files = npm.get_package_files(pkg_name)

            # Pattern detection
            findings = detector.scan_package(files)

            # Typosquat check
            typosquat_findings = typosquat.scan_package_name(pkg_name)
            findings.extend(typosquat_findings)

            code_chars = sum(len(f) for f in files.values())
            file_tokens = code_chars // 4 + 1000
            total_tokens += file_tokens
            scanned += 1
            findings_count += len(findings)

            if findings:
                for f in findings:
                    all_findings.append({
                        'package': pkg_name,
                        'rule_id': f.rule_id if hasattr(f, 'rule_id') else 'UNKNOWN',
                        'title': f.title if hasattr(f, 'title') else str(f),
                        'risk_level': f.risk_level.value if hasattr(f, 'risk_level') else 'unknown',
                    })

            elapsed = time.time() - start_time
            rate = total_tokens / elapsed if elapsed > 0 else 0
            risk = 'SAFE' if not findings else f'{len(findings)} findings'

            print(f'[{scanned:3d}/{len(unique_packages)}] {pkg_name:30s} | {len(files):5d} files | {file_tokens:>8,} tok | {rate:,.0f} tok/s | {risk}')

        except Exception as e:
            errors += 1
            print(f'[ERR] {pkg_name:30s} | {str(e)[:60]}')

    elapsed = time.time() - start_time
    print('=' * 80)
    print('BATCH SCAN REPORT:')
    print(f'  Duration: {elapsed:.0f}s ({elapsed/60:.1f} min)')
    print(f'  Packages scanned: {scanned}')
    print(f'  Errors: {errors}')
    print(f'  Total findings: {findings_count}')
    print(f'  TOTAL TOKENS BURNED: {total_tokens:,}')
    print(f'  Rate: {total_tokens/elapsed:,.0f} tokens/second')
    print(f'  Rate limiter: {rate_limiter.get_stats()}')

    if all_findings:
        with open('batch_scan_findings.json', 'w') as f:
            json.dump(all_findings, f, indent=2)
        print(f'  Findings saved to batch_scan_findings.json')


if __name__ == '__main__':
    main()
