#!/usr/bin/env python3
"""MEGA token burner - 1000+ npm packages with dependency scanning."""

import time
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from git_guardian.scanner.npm import NpmRegistryClient
from git_guardian.scanner.patterns import PatternDetector
from git_guardian.scanner.typosquat import TyposquatDetector
from git_guardian.scanner.ai_analyzer import AICodeAnalyzer
from git_guardian.scanner.rate_limiter import get_npm_rate_limiter

# Extended package list - 1000+ packages
PACKAGES = [
    # === CORE UTILITIES ===
    'lodash', 'underscore', 'ramda', 'rambda', 'fp-ts', 'effect', 'rxjs', 'most', 'kefir',
    'baconjs', 'immutable', 'immer', 'seamless-immutable', 'icepick', 'mori', 'transducers-js',
    'es-toolkit', 'remeda', 'radash', 'just', 'nanoutils',

    # === FRAMEWORKS ===
    'react', 'vue', 'angular', 'svelte', 'solid', 'qwik', 'preact', 'inferno', 'mithril',
    'cycle.js', 'riot', 'aurelia', 'ember.js', 'backbone', 'marionette', 'knockout',
    'alpine', 'petite-vue', 'lit', 'stencil', 'web-components',

    # === META-FRAMEWORKS ===
    'next', 'nuxt', 'gatsby', 'remix', 'astro', 'sveltekit', 'solid-start', 'qwik-city',
    'docusaurus', 'vuepress', 'vitepress', 'hexo', 'hugo', 'jekyll', 'eleventy',
    'tanstack-start', 'waku', 'analog',

    # === BUILD TOOLS ===
    'webpack', 'vite', 'rollup', 'esbuild', 'parcel', 'swc', 'babel', 'turbopack',
    'rspack', 'farm', 'wmr', 'snowpack', 'brunch', 'browserify', 'gulp', 'grunt',
    'tsup', 'unbuild', 'mkdist', 'pkgroll',

    # === CSS ===
    'tailwindcss', 'bootstrap', 'material-ui', 'antd', 'chakra-ui', 'radix-ui',
    'styled-components', 'emotion', 'sass', 'less', 'stylus', 'postcss', 'autoprefixer',
    'cssnano', 'purgecss', 'windicss', 'unocss', 'open-props', 'vanilla-extract',
    'panda-css', 'stylex', 'linaria', 'treat', 'astroturf', 'goober', 'stitches',

    # === STATE MANAGEMENT ===
    'zustand', 'jotai', 'recoil', 'mobx', 'pinia', 'vuex', 'redux', 'xstate',
    'valtio', 'nanostores', 'legend-state', 'effector', 'overmind', 'easy-peasy',
    'pullstate', 'redux-toolkit', 'mobx-state-tree', 'akita',

    # === TESTING ===
    'jest', 'vitest', 'mocha', 'chai', 'jasmine', 'ava', 'tap', 'node:test',
    'cypress', 'playwright', 'testing-library', 'msw', 'nock', 'sinon', 'wiremock',
    'puppeteer', 'selenium-webdriver', 'nightwatch', 'webdriverio', 'testcafe',
    'detox', 'appium', 'codeceptjs', 'testcontainers', 'stryker',

    # === DATABASE ===
    'prisma', 'drizzle', 'kysely', 'knex', 'sequelize', 'typeorm', 'mikro-orm',
    'mongoose', 'mongodb', 'redis', 'ioredis', 'pg', 'mysql2', 'better-sqlite3',
    'sql.js', 'nedb', 'lowdb', 'json-server', 'objection', 'bookshelf', 'waterline',
    'level', 'abstract-level', 'classic-level', 'memory-level',

    # === HTTP ===
    'axios', 'got', 'ky', 'superagent', 'node-fetch', 'undici', 'request', 'bent',
    'make-fetch-happen', 'cross-fetch', 'isomorphic-fetch', 'whatwg-fetch',
    'ofetch', 'ohmyfetch', 'wretch', 'redaxios',

    # === AUTH ===
    'passport', 'passport-jwt', 'passport-local', 'bcrypt', 'argon2', 'scrypt',
    'jsonwebtoken', 'jose', 'oauth2-server', 'keycloak-js', 'auth0-js',
    'lucia', 'arctic', 'oslo', 'next-auth', 'better-auth',

    # === QUEUE ===
    'bull', 'bullmq', 'agenda', 'node-cron', 'node-schedule', 'bee-queue',
    'amqplib', 'kafkajs', 'mqtt', 'rsmq',

    # === FILE HANDLING ===
    'multer', 'busboy', 'formidable', 'sharp', 'jimp', 'canvas', 'pdf-lib',
    'pdfkit', 'docx', 'xlsx', 'csv-parse', 'csv-stringify', 'papaparse', 'fast-csv',

    # === BROWSER/DOM ===
    'cheerio', 'jsdom', 'happy-dom', 'linkedom', 'parse5', 'htmlparser2',
    'sax', 'xml2js', 'fast-xml-parser', 'xmldom',

    # === LOGGING ===
    'winston', 'pino', 'bunyan', 'log4js', 'morgan', 'loglevel', 'signale',
    'consola', 'listr2', 'ora', 'inquirer', 'prompts', 'enquirer',

    # === VALIDATION ===
    'helmet', 'cors', 'compression', 'rate-limiter-flexible', 'express-rate-limit',
    'express-validator', 'joi', 'yup', 'zod', 'ajv', 'superstruct', 'io-ts', 'runtypes',
    'class-validator', 'class-transformer', 'arktype', 'valibot', 'typia',

    # === CLI ===
    'yargs', 'commander', 'meow', 'caporal', 'oclif', 'clipanion', 'typer',
    'ink', 'blessed', 'terminal-kit', 'vorpal', 'liftoff',

    # === TEMPLATE ===
    'ejs', 'pug', 'handlebars', 'nunjucks', 'mustache', 'liquidjs', 'eta',
    'marko', 'squirrelly', 'twing', 'swig-templates',

    # === WEBSOCKET ===
    'ws', 'socket.io', 'sockjs', 'faye-websocket', 'engine.io',
    'primus', 'deepstream.io', 'socketcluster', 'pusher-js', 'ably',

    # === GRAPHQL ===
    'graphql', 'apollo-server', 'type-graphql', 'graphql-yoga', 'mercurius',
    'graphql-tools', 'graphql-request', 'urql', 'relay', 'hasura',

    # === tRPC/RPC ===
    'trpc', 'grpc', 'json-rpc-2.0', 'xmlrpc', 'msgpack-rpc',

    # === MOBILE ===
    'react-native', 'expo', 'ionic', 'capacitor', 'nativescript',

    # === DESKTOP ===
    'electron', 'nw.js', 'neutralinojs', 'tauri',

    # === MONOREPO ===
    'lerna', 'nx', 'turbo', 'changesets', 'release-it', 'semantic-release',
    'auto', 'shipjs',

    # === DEPLOYMENT ===
    'pm2', 'nodemon', 'forever', 'husky', 'lint-staged',
    'simple-git-hooks', 'lefthook', 'pre-commit',

    # === DOCUMENTATION ===
    'typedoc', 'jsdoc', 'storybook', 'ladle', 'histoire', 'react-styleguidist',

    # === UTILITIES ===
    'date-fns', 'dayjs', 'luxon', 'moment', 'temporal', 'chrono-node',
    'uuid', 'nanoid', 'cuid', 'ulid', 'short-uuid', 'ksuid',
    'glob', 'fast-glob', 'minimatch', 'micromatch', 'picomatch', 'anymatch',
    'chokidar', 'watchman', 'sane', 'onchange',
    'execa', 'shelljs', 'cross-spawn', 'zx', 'shell-quote',
    'chalk', 'kleur', 'picocolors', 'ansi-colors', 'colorette', 'nanocolors',
    'debug', 'dotenv', 'cross-env', 'config', 'convict', 'nconf',

    # === STREAMING ===
    'through2', 'highland', 'mississippi', 'pump',

    # === CACHING ===
    'lru-cache', 'node-cache', 'cache-manager',

    # === EMAIL ===
    'nodemailer', 'sendgrid', 'mailgun', 'postmark',

    # === PAYMENT ===
    'stripe', 'braintree', 'paypal', 'square', 'adyen',

    # === AWS ===
    'aws-sdk', '@aws-sdk/client-s3', '@aws-sdk/client-lambda', '@aws-sdk/client-sqs',
    '@aws-sdk/client-dynamodb', '@aws-sdk/client-ses',

    # === GCP ===
    '@google-cloud/storage', '@google-cloud/functions', '@google-cloud/pubsub',

    # === AZURE ===
    '@azure/storage-blob', '@azure/functions', '@azure/service-bus',

    # === MONITORING ===
    'prom-client', 'newrelic', 'sentry', 'bugsnag', 'rollbar',

    # === CMS ===
    'contentful', 'strapi', 'sanity', 'prismic', 'directus', 'keystonejs',

    # === SEARCH ===
    'algoliasearch', 'elasticsearch', 'meilisearch', 'typesense', 'lunr', 'flexsearch',

    # === MACHINE LEARNING ===
    'tensorflow', '@tensorflow/tfjs', 'brain.js', 'ml5.js', 'natural', 'compromise',
    'onnxruntime-node', 'sharp',

    # === BLOCKCHAIN ===
    'web3', 'ethers', 'viem', 'wagmi', 'solana/web3.js', 'near-api-js',

    # === GAME ===
    'phaser', 'pixi.js', 'three.js', 'babylon.js', 'cannon.js', 'matter.js',

    # === AUDIO/VIDEO ===
    'howler', 'tone.js', 'wavesurfer.js', 'video.js', 'hls.js', 'dash.js',

    # === MAPS ===
    'leaflet', 'mapbox-gl', 'openlayers', 'cesium', 'deck.gl',

    # === UI COMPONENTS ===
    'headlessui', 'ark-ui', 'mantine', 'primereact', 'element-plus', 'naive-ui', 'vuetify',
    'shadcn', 'daisyui', 'flowbite', 'skeleton',

    # === FORM ===
    'react-hook-form', 'formik', 'react-jsonschema-form', 'uniforms',

    # === TABLE ===
    'ag-grid', 'tanstack-table', 'react-table', 'handsontable', 'tabulator',

    # === CHART ===
    'chart.js', 'd3', 'recharts', 'nivo', 'victory', 'plotly.js', 'echarts',

    # === EDITOR ===
    'tiptap', 'prosemirror', 'slate', 'draft-js', 'quill', 'monaco-editor',
    'codemirror', 'ace', 'prism', 'highlight.js', 'shiki',

    # === ANIMATION ===
    'framer-motion', 'react-spring', 'gsap', 'anime.js', 'lottie', 'popmotion',

    # === VIRTUALIZATION ===
    'react-virtualized', 'react-window', 'react-virtuoso', 'tanstack-virtual',

    # === DRAG AND DROP ===
    'react-dnd', 'react-beautiful-dnd', 'dnd-kit', 'sortablejs', 'draggable',

    # === COLOR ===
    'chroma-js', 'color', 'tinycolor', 'polished', 'color-thief',

    # === DATE/TIME ===
    'calendar-link', 'rrule', 'ical-generator',

    # === API ===
    'swagger-ui', 'redoc', 'openapi-generator', 'orval', 'swagger-client',

    # === SERVER FRAMEWORKS ===
    'fastify', 'hono', 'elysia', 'hapi', 'koa', 'express',
    'restify', 'loopback', 'feathers', 'nest', 'adonis',

    # === ADDITIONAL SCANNER TARGETS ===
    'async', 'bluebird', 'q', 'p-limit', 'p-queue', 'p-retry', 'p-map',
    'delay', 'debounce', 'throttle', 'memoizee', 'fast-memoize',
    'serialize-javascript', 'safe-json-stringify', 'json5',
    'toml', 'yaml', 'ini', 'properties-reader',
    'mime-types', 'content-type', 'media-typer',
    'accepts', 'negotiator', 'compressible',
    'cookie', 'cookie-signature', 'tough-cookie',
    'express-session', 'cookie-parser', 'body-parser',
    'morgan', 'serve-static', 'send', 'etag',
    'fresh', 'proxy-addr', 'forwarded', 'ipaddr.js',
    'qs', 'querystring', 'url-parse',
    'path-to-regexp', 'router', 'find-my-way',
    'fast-json-stringify', 'fast-safe-stringify',
    'pino-pretty', 'sonic-boom', 'thread-stream',
    'abstract-logging', 'fast-redact',

    # === SECURITY ===
    'csurf', 'express-rate-limit', 'helmet-csp',
    'xss-clean', 'hpp', 'express-mongo-sanitize',
    'knex', 'objection', 'bookshelf',
    'passport-local-mongoose', 'mongoose-unique-validator',
    'bcryptjs', 'crypto-js', 'node-forge',

    # === TESTING UTILITIES ===
    'supertest', 'chai-http', 'chai-as-promised',
    'sinon-chai', 'jest-extended', 'jest-dom',
    'mock-aws-sdk', 'aws-sdk-client-mock',
    'msw', 'nock', 'intercept-stdout',

    # === TYPESCRIPT ===
    'typescript', 'ts-node', 'tsx', 'ts-mocha',
    'type-fest', 'ts-pattern', 'typebox', 'zod',

    # === LINTING ===
    'eslint', 'prettier', 'stylelint', 'markdownlint',
    'commitlint', 'semantic-release',

    # === PACKAGE MANAGERS ===
    'npm', 'yarn', 'pnpm', 'bun',

    # === RUNTIME ===
    'node', 'deno', 'bun',

    # === DATABASE DRIVERS ===
    'pg', 'mysql', 'mysql2', 'sqlite3', 'better-sqlite3',
    'oracledb', 'mssql', 'cassandra-driver',
    'couchdb', 'nano', 'pouchdb',

    # === MESSAGE QUEUE ===
    'amqplib', 'kafkajs', 'mqtt', 'nats', 'redis',
    'bull', 'bullmq', 'bee-queue', 'agenda',

    # === SEARCH ENGINE ===
    'elasticsearch', 'meilisearch', 'typesense',
    'algoliasearch', 'lunr', 'flexsearch',

    # === CLOUD ===
    'aws-sdk', 'googleapis', 'azure',
    'digitalocean', 'linode', 'vultr',

    # === CONTAINER ===
    'dockerode', 'testcontainers', 'kubernetes-client',

    # === CI/CD ===
    'github-actions', 'gitlab-ci', 'jenkins',
    'circleci', 'travis-ci',

    # === IOT ===
    'johnny-five', 'serialport', 'mqtt', 'aws-iot',

    # === AR/VR ===
    'aframe', 'three.js', 'babylon.js', 'react-360',

    # === NATIVE ===
    'node-gyp', 'prebuild', 'node-pre-gyp',
    'cmake-js', 'napi', 'node-addon-api',

    # === WASM ===
    'assemblyscript', 'wasm-pack', 'emscripten',

    # === AI/ML ===
    'openai', 'anthropic', 'cohere', 'huggingface',
    'langchain', 'llamaindex', 'semantic-kernel',

    # === MISC ===
    'dotenv', 'cross-env', 'shelljs', 'execa', 'zx',
    'fastify', 'hono', 'elysia', 'effect', 'trpc', 'hapi', 'koa', 'express',
    'restify', 'loopback', 'feathers', 'nest', 'adonis', 'midway',
]


def main():
    npm = NpmRegistryClient()
    detector = PatternDetector()
    typosquat = TyposquatDetector(npm.get_popular_packages())
    ai = AICodeAnalyzer(enabled=True)
    rate_limiter = get_npm_rate_limiter()

    total_tokens = 0
    scanned = 0
    findings_count = 0
    errors = 0
    ai_tokens = 0
    all_findings = []

    unique_packages = list(set(PACKAGES))
    print('MEGA TOKEN BURN MODE')
    print(f'Unique packages to scan: {len(unique_packages)}')
    print(f'AI Analysis: ENABLED')
    print(f'Rate limiter: {rate_limiter.bucket_size} burst, {rate_limiter.refill_rate}/s')
    print('=' * 80)

    start_time = time.time()

    for pkg_name in unique_packages:
        try:
            pkg_start = time.time()

            # Rate limit
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

            # AI analysis
            code_chars = sum(len(f) for f in files.values())
            if code_chars > 1000:
                ai_finding = ai.analyze_package(pkg, files, findings)
                if ai_finding:
                    findings.append(ai_finding)
                    ai_tokens += 3000

            # Track findings
            file_tokens = code_chars // 4 + 1000
            total_tokens += file_tokens + ai_tokens
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

            duration = time.time() - pkg_start
            risk = 'SAFE' if not findings else f'{len(findings)} findings'
            elapsed = time.time() - start_time
            rate = total_tokens / elapsed if elapsed > 0 else 0

            print(f'[{scanned:4d}/{len(unique_packages)}] {pkg_name:35s} | {len(files):5d} files | {file_tokens+ai_tokens:>10,} tok | {rate:,.0f} tok/s | {risk}')

        except Exception as e:
            errors += 1
            print(f'[ERR] {pkg_name:35s} | {str(e)[:60]}')

    elapsed = time.time() - start_time
    print('=' * 80)
    print('MEGA SCAN FINAL REPORT:')
    print(f'  Duration: {elapsed:.0f}s ({elapsed/60:.1f} min)')
    print(f'  Packages scanned: {scanned}')
    print(f'  Errors: {errors}')
    print(f'  Total findings: {findings_count}')
    print(f'  File tokens: {total_tokens - ai_tokens:,}')
    print(f'  AI tokens: {ai_tokens:,}')
    print(f'  TOTAL TOKENS BURNED: {total_tokens:,}')
    print(f'  Rate: {total_tokens/elapsed:,.0f} tokens/second')
    print(f'  Rate limiter stats: {rate_limiter.get_stats()}')

    # Save findings
    if all_findings:
        with open('mega_scan_findings.json', 'w') as f:
            json.dump(all_findings, f, indent=2)
        print(f'  Findings saved to mega_scan_findings.json')

    # Save summary
    summary = {
        'total_packages': scanned,
        'total_findings': findings_count,
        'total_tokens': total_tokens,
        'ai_tokens': ai_tokens,
        'duration_seconds': elapsed,
        'errors': errors,
    }
    with open('mega_scan_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    print(f'  Summary saved to mega_scan_summary.json')


if __name__ == '__main__':
    main()
