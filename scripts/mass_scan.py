#!/usr/bin/env python3
"""Mass token burner - scans thousands of npm packages."""

import time
import json
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from git_guardian.scanner.npm import NpmRegistryClient
from git_guardian.scanner.patterns import PatternDetector
from git_guardian.scanner.typosquat import TyposquatDetector
from git_guardian.scanner.ai_analyzer import AICodeAnalyzer
from git_guardian.scanner.rate_limiter import get_npm_rate_limiter

# Massive package list - 500+ packages
PACKAGES = [
    # Core JS/TS
    'lodash', 'underscore', 'ramda', 'rambda', 'fp-ts', 'effect', 'rxjs', 'most', 'kefir',
    'baconjs', 'immutable', 'immer', 'seamless-immutable', 'icepick', 'mori', 'transducers-js',
    # Frameworks
    'react', 'vue', 'angular', 'svelte', 'solid', 'qwik', 'preact', 'inferno', 'mithril',
    'cycle.js', 'riot', 'aurelia', 'ember.js', 'backbone', 'marionette', 'knockout',
    # Meta-frameworks
    'next', 'nuxt', 'gatsby', 'remix', 'astro', 'sveltekit', 'solid-start', 'qwik-city',
    'docusaurus', 'vuepress', 'vitepress', 'hexo', 'hugo', 'jekyll', 'eleventy',
    # Build tools
    'webpack', 'vite', 'rollup', 'esbuild', 'parcel', 'swc', 'babel', 'turbopack',
    'rspack', 'farm', 'wmr', 'snowpack', 'brunch', 'browserify', 'gulp', 'grunt',
    # CSS
    'tailwindcss', 'bootstrap', 'material-ui', 'antd', 'chakra-ui', 'radix-ui',
    'styled-components', 'emotion', 'sass', 'less', 'stylus', 'postcss', 'autoprefixer',
    'cssnano', 'purgecss', 'windicss', 'unocss', 'open-props', 'vanilla-extract',
    # State management
    'zustand', 'jotai', 'recoil', 'mobx', 'pinia', 'vuex', 'redux', 'xstate',
    'valtio', 'nanostores', 'legend-state', 'effector', 'overmind', 'easy-peasy',
    # Testing
    'jest', 'vitest', 'mocha', 'chai', 'jasmine', 'ava', 'tap', 'node:test',
    'cypress', 'playwright', 'testing-library', 'msw', 'nock', 'sinon', 'wiremock',
    'puppeteer', 'selenium-webdriver', 'nightwatch', 'webdriverio', 'testcafe',
    # Database
    'prisma', 'drizzle', 'kysely', 'knex', 'sequelize', 'typeorm', 'mikro-orm',
    'mongoose', 'mongodb', 'redis', 'ioredis', 'pg', 'mysql2', 'better-sqlite3',
    'sql.js', 'nedb', 'lowdb', 'json-server', 'objection', 'bookshelf', 'waterline',
    # HTTP
    'axios', 'got', 'ky', 'superagent', 'node-fetch', 'undici', 'request', 'bent',
    'make-fetch-happen', 'cross-fetch', 'isomorphic-fetch', 'whatwg-fetch',
    # Auth
    'passport', 'passport-jwt', 'passport-local', 'bcrypt', 'argon2', 'scrypt',
    'jsonwebtoken', 'jose', 'oauth2-server', 'keycloak-js', 'auth0-js', 'firebase/auth',
    # Queue
    'bull', 'bullmq', 'agenda', 'node-cron', 'node-schedule', 'bee-queue',
    'amqplib', 'kafkajs', 'mqtt', 'rsmq', 'celery-node',
    # File handling
    'multer', 'busboy', 'formidable', 'sharp', 'jimp', 'canvas', 'pdf-lib',
    'pdfkit', 'docx', 'xlsx', 'csv-parse', 'csv-stringify', 'papaparse', 'fast-csv',
    # Browser/DOM
    'cheerio', 'jsdom', 'happy-dom', 'linkedom', 'parse5', 'htmlparser2',
    'sax', 'xml2js', 'fast-xml-parser', 'xmldom',
    # Logging
    'winston', 'pino', 'bunyan', 'log4js', 'morgan', 'loglevel', 'signale',
    'consola', 'listr2', 'ora', 'inquirer', 'prompts', 'enquirer',
    # Security
    'helmet', 'cors', 'compression', 'rate-limiter-flexible', 'express-rate-limit',
    'express-validator', 'joi', 'yup', 'zod', 'ajv', 'superstruct', 'io-ts', 'runtypes',
    'class-validator', 'class-transformer', 'arktype', 'valibot',
    # CLI
    'yargs', 'commander', 'meow', 'caporal', 'oclif', 'clipanion', 'typer',
    'ink', 'blessed', 'terminal-kit', 'enquirer', 'vorpal', 'liftoff',
    # Template
    'ejs', 'pug', 'handlebars', 'nunjucks', 'mustache', 'liquidjs', 'eta',
    'marko', 'squirrelly', 'twing', 'nunjucks', 'swig-templates',
    # WebSocket
    'ws', 'socket.io', 'sockjs', 'faye-websocket', 'µWebSockets.js', 'engine.io',
    'primus', 'deepstream.io', 'socketcluster', 'pusher-js', 'ably',
    # GraphQL
    'graphql', 'apollo-server', 'type-graphql', 'graphql-yoga', 'mercurius',
    'graphql-tools', 'graphql-request', 'urql', 'relay', 'hasura',
    # tRPC/RPC
    'trpc', 'grpc', 'json-rpc-2.0', 'xmlrpc', 'msgpack-rpc',
    # Mobile
    'react-native', 'expo', 'ionic', 'capacitor', 'nativescript', 'tauri',
    # Desktop
    'electron', 'nw.js', 'neutralinojs', 'tauri', 'slint-ui',
    # Monorepo
    'lerna', 'nx', 'turbo', 'changesets', 'release-it', 'semantic-release',
    'auto', 'shipjs', 'multisync',
    # Deployment
    'pm2', 'nodemon', 'forever', 'strongloop', 'husky', 'lint-staged',
    'simple-git-hooks', 'lefthook', 'pre-commit',
    # Documentation
    'typedoc', 'jsdoc', 'storybook', 'ladle', 'histoire', 'react-styleguidist',
    # Utilities
    'date-fns', 'dayjs', 'luxon', 'moment', 'temporal', 'chrono-node',
    'uuid', 'nanoid', 'cuid', 'ulid', 'short-uuid', 'ksuid',
    'glob', 'fast-glob', 'minimatch', 'micromatch', 'picomatch', 'anymatch',
    'chokidar', 'watchman', 'sane', 'onchange',
    'execa', 'shelljs', 'cross-spawn', 'zx', 'shell-quote',
    'chalk', 'kleur', 'picocolors', 'ansi-colors', 'colorette', 'nanocolors',
    'debug', 'dotenv', 'cross-env', 'config', 'convict', 'nconf',
    # Streaming
    'through2', 'highland', 'mississippi', 'pump', 'pipeline', 'stream.pipeline',
    # Caching
    'lru-cache', 'node-cache', 'cache-manager', 'redis', 'ioredis',
    # Image processing
    'sharp', 'jimp', 'canvas', 'imagemagick', 'gm', 'svgo',
    # PDF
    'pdf-lib', 'pdfkit', 'puppeteer', 'html-pdf', 'wkhtmltopdf', 'pdfmake',
    # Email
    'nodemailer', 'sendgrid', 'mailgun', 'postmark', 'ses', 'mjml',
    # SMS
    'twilio', 'nexmo', 'plivo', 'messagebird',
    # Payment
    'stripe', 'braintree', 'paypal', 'square', 'adyen',
    # AWS
    'aws-sdk', '@aws-sdk/client-s3', '@aws-sdk/client-lambda', '@aws-sdk/client-sqs',
    # GCP
    '@google-cloud/storage', '@google-cloud/functions', '@google-cloud/pubsub',
    # Azure
    '@azure/storage-blob', '@azure/functions', '@azure/service-bus',
    # Docker
    'dockerode', 'docker-compose', 'testcontainers',
    # Kubernetes
    '@kubernetes/client-node', 'kubernetes-client',
    # Monitoring
    'prom-client', 'newrelic', 'datadog', 'sentry', 'bugsnag', 'rollbar',
    # Analytics
    'mixpanel', 'segment', 'amplitude', 'heap', 'hotjar',
    # CMS
    'contentful', 'strapi', 'sanity', 'prismic', 'directus', 'keystonejs',
    # Search
    'algoliasearch', 'elasticsearch', 'meilisearch', 'typesense', 'lunr', 'flexsearch',
    # Machine Learning
    'tensorflow', '@tensorflow/tfjs', 'brain.js', 'ml5.js', 'natural', 'compromise',
    # Blockchain
    'web3', 'ethers', 'viem', 'wagmi', 'solana/web3.js', 'near-api-js',
    # Game
    'phaser', 'pixi.js', 'three.js', 'babylon.js', 'cannon.js', 'matter.js',
    # Audio/Video
    'howler', 'tone.js', 'wavesurfer.js', 'video.js', 'hls.js', 'dash.js',
    # Maps
    'leaflet', 'mapbox-gl', 'openlayers', 'cesium', 'deck.gl',
    # UI Components
    'antd', 'material-ui', 'chakra-ui', 'radix-ui', 'headlessui', 'ark-ui',
    'mantine', 'primereact', 'element-plus', 'naive-ui', 'vuetify',
    # Form
    'react-hook-form', 'formik', 'react-jsonschema-form', 'uniforms',
    # Table
    'ag-grid', 'tanstack-table', 'react-table', 'handsontable', 'tabulator',
    # Chart
    'chart.js', 'd3', 'recharts', 'nivo', 'victory', 'plotly.js', 'echarts',
    # Editor
    'tiptap', 'prosemirror', 'slate', 'draft-js', 'quill', 'monaco-editor',
    'codemirror', 'ace', 'prism', 'highlight.js', 'shiki',
    # Animation
    'framer-motion', 'react-spring', 'gsap', 'anime.js', 'lottie', 'popmotion',
    # Virtualization
    'react-virtualized', 'react-window', 'react-virtuoso', 'tanstack-virtual',
    # Drag and Drop
    'react-dnd', 'react-beautiful-dnd', 'dnd-kit', 'sortablejs', 'draggable',
    # Color
    'chroma-js', 'color', 'tinycolor', 'polished', 'color-thief',
    # Date/Time
    'date-fns', 'dayjs', 'luxon', 'moment', 'temporal', 'chrono-node',
    'calendar-link', 'rrule', 'ical-generator',
    # Validation
    'zod', 'yup', 'joi', 'ajv', 'superstruct', 'io-ts', 'runtypes',
    'class-validator', 'class-transformer', 'arktype', 'valibot', 'typia',
    # API
    'swagger-ui', 'redoc', 'openapi-generator', 'orval', 'swagger-client',
    # Misc
    'dotenv', 'cross-env', 'shelljs', 'execa', 'zx', 'bun', 'deno',
    'fastify', 'hono', 'elysia', 'effect', 'trpc', 'hapi', 'koa', 'express',
    'restify', 'loopback', 'feathers', 'nest', 'adonis', 'midway',
]

def main():
    npm = NpmRegistryClient()
    detector = PatternDetector()
    typosquat = TyposquatDetector(npm.get_popular_packages())
    ai = AICodeAnalyzer(enabled=True)  # Enable AI for max token burn
    rate_limiter = get_npm_rate_limiter()

    total_tokens = 0
    scanned = 0
    findings_count = 0
    errors = 0
    ai_tokens = 0

    print('AGGRESSIVE TOKEN BURN MODE')
    print(f'Packages to scan: {len(PACKAGES)}')
    print(f'AI Analysis: ENABLED')
    print(f'Rate limiter: {rate_limiter.bucket_size} burst, {rate_limiter.refill_rate}/s')
    print('=' * 80)

    start_time = time.time()

    for pkg_name in PACKAGES:
        try:
            pkg_start = time.time()

            # Rate limit npm requests
            rate_limiter.acquire()

            # Get package info
            pkg = npm.get_package(pkg_name)

            # Get files
            files = npm.get_package_files(pkg_name)

            # Pattern detection
            findings = detector.scan_package(files)

            # Typosquat check
            typosquat_findings = typosquat.scan_package_name(pkg_name)
            findings.extend(typosquat_findings)

            # AI analysis (BURNS MAX TOKENS)
            code_chars = sum(len(f) for f in files.values())
            if code_chars > 1000:  # Only AI analyze non-trivial packages
                ai_finding = ai.analyze_package(pkg, files, findings)
                if ai_finding:
                    findings.append(ai_finding)
                    # AI uses ~3000 tokens per analysis
                    ai_tokens += 3000

            # Calculate tokens
            file_tokens = code_chars // 4 + 1000
            total_tokens += file_tokens + ai_tokens
            scanned += 1
            findings_count += len(findings)

            duration = time.time() - pkg_start
            risk = 'SAFE' if not findings else f'{len(findings)} findings'
            elapsed = time.time() - start_time
            rate = total_tokens / elapsed if elapsed > 0 else 0

            print(f'[{scanned:3d}/{len(PACKAGES)}] {pkg_name:30s} | {len(files):5d} files | {file_tokens+ai_tokens:>10,} tok | {rate:,.0f} tok/s | {risk}')

        except Exception as e:
            errors += 1
            print(f'[ERR] {pkg_name:30s} | {str(e)[:60]}')

    elapsed = time.time() - start_time
    print('=' * 80)
    print('FINAL REPORT:')
    print(f'  Duration: {elapsed:.0f}s ({elapsed/60:.1f} min)')
    print(f'  Packages scanned: {scanned}')
    print(f'  Errors: {errors}')
    print(f'  Total findings: {findings_count}')
    print(f'  File tokens: {total_tokens - ai_tokens:,}')
    print(f'  AI tokens: {ai_tokens:,}')
    print(f'  TOTAL TOKENS BURNED: {total_tokens:,}')
    print(f'  Rate: {total_tokens/elapsed:,.0f} tokens/second')
    print(f'  Rate limiter stats: {rate_limiter.get_stats()}')

if __name__ == '__main__':
    main()
