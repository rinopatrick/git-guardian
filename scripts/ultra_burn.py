#!/usr/bin/env python3
"""ULTRA TOKEN BURNER — ALL 11 services on 100 packages.

Services: patterns + AI + deep-analysis + license + health + audit + network
          + malware + lockfile + advisory + sbom + report

Expected burn: 100k-300k tokens per package. 10M-30M total.
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
from git_guardian.services.lockfile_analyzer import LockfileAnalyzer
from git_guardian.services.advisory_client import AdvisoryClient
from git_guardian.services.sbom_service import SBOMService
from git_guardian.services.report_service import ReportService

# Top 100 most downloaded npm packages
PACKAGES = [
    'lodash', 'chalk', 'react', 'express', 'axios', 'commander', 'vue',
    'moment', 'uuid', 'classnames', 'prop-types', 'react-dom', 'tslib',
    'debug', 'dotenv', 'glob', 'minimist', 'mkdirp', 'bluebird', 'underscore',
    'semver', 'request', 'body-parser', 'webpack', 'babel-core', 'eslint',
    'typescript', 'next', 'angular', 'jquery', 'socket.io', 'mongoose',
    'sequelize', 'pg', 'mysql', 'redis', 'jsonwebtoken', 'bcrypt',
    'passport', 'cors', 'helmet', 'morgan', 'winston', 'pino',
    'zod', 'joi', 'yup', 'ajv', 'date-fns', 'dayjs', 'ramda',
    'rxjs', 'immutable', 'mobx', 'redux', 'zustand', 'pinia',
    'tailwindcss', 'postcss', 'sass', 'less', 'styled-components',
    'vite', 'esbuild', 'rollup', 'webpack', 'parcel',
    'jest', 'mocha', 'chai', 'sinon', 'cypress', 'playwright',
    'puppeteer', 'sharp', 'canvas', 'node-fetch', 'got', 'superagent',
    'graphql', 'apollo-server', 'prisma', 'typeorm', 'knex',
    'fastify', 'koa', 'hapi', 'nestjs', 'adonis',
    'electron', 'react-native', 'expo', 'svelte', 'solid',
    'preact', 'lit', 'alpine', 'htmx', 'three', 'd3',
    'chart.js', 'leaflet', 'openai', 'langchain', 'tensorflow',
    'ethers', 'web3', 'stripe', 'twilio', 'nodemailer',
]

import json as json_mod


def run_all_services(npm, package_name, stats):
    """Run ALL 11 services on a single package."""
    start = time.time()
    results = {}

    try:
        pkg_info = npm.get_package(package_name)
        files = npm.get_package_files(package_name)

        # 1. Pattern detection
        detector = PatternDetector()
        pattern_findings = detector.scan_package(files)
        results['patterns'] = len(pattern_findings)

        # 2. AI analysis
        ai = AICodeAnalyzer(enabled=True)
        ai_finding = ai.analyze_package(pkg_info, files, pattern_findings)
        results['ai_finding'] = 1 if ai_finding else 0

        # 3. Deep analysis (ALL files)
        deep = DeepAnalyzer()
        deep_result = deep.analyze_package(pkg_info, files)
        results['deep_files'] = deep_result.files_analyzed
        results['deep_tokens'] = deep_result.total_tokens
        results['deep_findings'] = len(deep_result.findings)

        # 4. License check
        lic = LicenseScanner()
        lic_report = lic.scan_package(pkg_info)
        results['license'] = lic_report.license_type
        results['license_issues'] = len(lic_report.findings)

        # 5. Health score
        health = HealthScorer()
        health_report = health.score_package(pkg_info)
        results['health_score'] = health_report.overall_score
        results['health_grade'] = health_report.grade

        # 6. Package audit
        auditor = PackageAuditor()
        try:
            pkg_json = json_mod.loads(files.get("package.json", "{}"))
            audit_report = auditor.audit_package_json(pkg_json, package_name)
            results['audit_issues'] = len(audit_report.findings)
        except Exception:
            results['audit_issues'] = 0

        # 7. Network profiling
        profiler = NetworkProfiler()
        net_report = profiler.profile_package(package_name, files)
        results['endpoints'] = net_report.endpoint_count
        results['has_telemetry'] = net_report.has_telemetry

        # 8. Malware DB
        malware_db = MalwareDatabase()
        mal_findings, _ = malware_db.scan_package(package_name, pkg_info.latest_version, files)
        results['malware'] = len(mal_findings)

        # 9. Lockfile analysis
        lockfile = LockfileAnalyzer()
        lockfile_findings = 0
        if "package-lock.json" in files:
            lr = lockfile.analyze_npm_lockfile(files["package-lock.json"], package_name)
            lockfile_findings += len(lr.findings)
        if "yarn.lock" in files:
            lr = lockfile.analyze_yarn_lockfile(files["yarn.lock"], package_name)
            lockfile_findings += len(lr.findings)
        results['lockfile_issues'] = lockfile_findings

        # 10. Advisory check
        adv_client = AdvisoryClient()
        adv_report = adv_client.scan_package(package_name, pkg_info.latest_version)
        results['advisories'] = len(adv_report.advisories)

        # 11. SBOM generation
        sbom_svc = SBOMService()
        deps = {}
        if pkg_info.versions:
            for dep_name, dep_ver in pkg_info.versions[-1].dependencies.items():
                deps[dep_name] = {"version": dep_ver}
        cyclonedx = sbom_svc.generate_cyclonedx(pkg_info, deps)
        results['sbom_components'] = cyclonedx.component_count

        # 12. AI Report (4 AI calls — biggest token burner)
        report_svc = ReportService()
        network_summary = f"{net_report.endpoint_count} endpoints"
        sec_report = report_svc.generate_report(
            pkg_info,
            pattern_findings,
            {"total": len(deps), "packages": {k: v for k, v in list(deps.items())[:20]}},
            adv_report.findings,
            network_summary,
            health_report.overall_score,
        )
        results['report_tokens'] = sec_report.total_tokens

        duration = time.time() - start
        results['duration'] = duration

        total_findings = (len(pattern_findings) + (1 if ai_finding else 0) +
                         len(deep_result.findings) + len(lic_report.findings) +
                         len(net_report.findings) + len(mal_findings) +
                         lockfile_findings + len(adv_report.findings))
        results['total_findings'] = total_findings
        results['total_tokens'] = deep_result.total_tokens + sec_report.total_tokens

        return results

    except Exception as e:
        results['error'] = str(e)[:100]
        results['duration'] = time.time() - start
        return results


def main():
    print("=" * 120)
    print("ULTRA TOKEN BURNER — ALL 11 SERVICES")
    print(f"Packages: {len(PACKAGES)}")
    print("Services: patterns + AI + deep + license + health + audit + network + malware + lockfile + advisory + sbom + report")
    print("=" * 120)

    npm = NpmRegistryClient()
    detector = PatternDetector()
    popular = npm.get_popular_packages()
    typosquat = TyposquatDetector(popular)

    stats = {'total_tokens': 0, 'total_findings': 0, 'total_packages': 0, 'total_errors': 0}
    results_log = []

    for i, pkg in enumerate(PACKAGES):
        try:
            result = run_all_services(npm, pkg, stats)
            stats['total_packages'] += 1

            if 'error' in result:
                stats['total_errors'] += 1
                status = f"ERROR: {result['error'][:60]}"
            else:
                stats['total_findings'] += result.get('total_findings', 0)
                stats['total_tokens'] += result.get('total_tokens', 0)
                status = (
                    f"{result.get('duration', 0):.0f}s | "
                    f"pat:{result.get('patterns', 0)} "
                    f"deep:{result.get('deep_findings', 0)} "
                    f"lic:{result.get('license_issues', 0)} "
                    f"health:{result.get('health_grade', '?')} "
                    f"audit:{result.get('audit_issues', 0)} "
                    f"net:{result.get('endpoints', 0)} "
                    f"mal:{result.get('malware', 0)} "
                    f"lock:{result.get('lockfile_issues', 0)} "
                    f"adv:{result.get('advisories', 0)} "
                    f"sbom:{result.get('sbom_components', 0)} "
                    f"| {result.get('total_tokens', 0):,} tok"
                )

            print(f"[{i+1:3d}/{len(PACKAGES)}] {pkg:25s} | {status}")
            results_log.append({'package': pkg, **result})

        except KeyboardInterrupt:
            print("\n\nInterrupted!")
            break
        except Exception as e:
            print(f"[{i+1:3d}/{len(PACKAGES)}] {pkg:25s} | EXCEPTION: {e}")
            stats['total_errors'] += 1

    print("\n" + "=" * 120)
    print("ULTRA BURN COMPLETE")
    print(f"Packages scanned: {stats['total_packages']}/{len(PACKAGES)}")
    print(f"Total findings: {stats['total_findings']}")
    print(f"Total tokens: {stats['total_tokens']:,}")
    print(f"Errors: {stats['total_errors']}")
    print("=" * 120)

    output_file = Path(__file__).parent.parent / "ultra_burn_results.json"
    with open(output_file, "w") as f:
        json.dump({'stats': stats, 'results': results_log}, f, indent=2, default=str)
    print(f"\nResults saved to: {output_file}")

    npm.close()


if __name__ == "__main__":
    main()
