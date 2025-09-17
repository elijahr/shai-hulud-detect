#!/usr/bin/env python3
"""
Shai-Hulud NPM Supply Chain Attack Detection Script
Detects indicators of compromise from the September 2025 npm attack using concurrent processing
Usage: ./shai-hulud-detector.py <directory_to_scan>
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
try:
    from importlib.resources import files
except ImportError:
    # Python < 3.9 fallback
    from importlib_resources import files

from tqdm import tqdm

# Color codes for output
class Colors:
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    GREEN = '\033[0;32m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

class RiskLevel(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class Finding:
    path: str
    risk_level: RiskLevel
    category: str
    description: str
    details: str = ""

class ShaiHuludDetector:
    """Simple Shai-Hulud attack detector using concurrent futures."""

    def __init__(self, verbose: bool = False, paranoid: bool = False, max_workers: int = None, show_progress: bool = True):
        self.verbose = verbose
        self.paranoid = paranoid
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) + 4)
        self.show_progress = show_progress

        # Known malicious hash from Shai-Hulud attack
        self.malicious_hash = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"

        # Results storage
        self.findings: List[Finding] = []
        self.stats = {
            'files_scanned': 0,
            'json_files_analyzed': 0,
            'hashes_checked': 0,
            'directories_processed': 0,
            'scan_time_seconds': 0.0
        }

        # Progress tracking
        self.current_step = 0
        self.total_steps = 9

        # Load compromised packages
        self.compromised_packages = self._load_compromised_packages()
        self.affected_namespaces = {
            '@ctrl', '@crowdstrike', '@art-ws', '@ngx', '@nativescript-community',
            '@ahmedhfarag', '@operato', '@teselagen', '@things-factory', '@hestjs', '@nstudio'
        }

        # Compiled regex patterns for performance
        self._compile_patterns()

    def _load_compromised_packages(self) -> Set[str]:
        """Load compromised packages from package data."""
        packages = set()

        try:
            # Load from package resources (root file included via package data)
            package_files = files("shai_hulud_detector")
            packages_file = package_files / "../compromised-packages.txt"

            with packages_file.open('r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        packages.add(line)

        except (FileNotFoundError, ModuleNotFoundError) as e:
            print(f"{Colors.RED}FATAL ERROR: Required file 'compromised-packages.txt' not found in package data{Colors.NC}")
            print(f"{Colors.RED}This file contains the critical list of 270+ compromised packages.{Colors.NC}")
            print(f"{Colors.RED}Install via: pip install shai-hulud-detector{Colors.NC}")
            print(f"{Colors.RED}Error: {e}{Colors.NC}")
            sys.exit(1)

        if not packages:
            print(f"{Colors.RED}FATAL ERROR: No valid packages found in 'compromised-packages.txt'{Colors.NC}")
            print(f"{Colors.RED}The file exists but contains no package entries.{Colors.NC}")
            sys.exit(1)

        return packages

    def _compile_patterns(self):
        """Compile regex patterns for performance."""
        self.suspicious_patterns = {
            'webhook_endpoint': re.compile(r'bb8ca5f6-4175-45d2-b042-fc9ebb8170b7', re.IGNORECASE),
            'webhook_site': re.compile(r'webhook\.site', re.IGNORECASE),
            'trufflehog_refs': re.compile(r'trufflehog|secret.*scan|credential.*harvest', re.IGNORECASE),
            'suspicious_postinstall': re.compile(r'(curl|wget|eval)\s+.*\$', re.IGNORECASE),
            'malicious_workflow': re.compile(r'shai-hulud-workflow\.yml', re.IGNORECASE)
        }

        if self.paranoid:
            self.suspicious_patterns.update({
                'suspicious_urls': re.compile(r'(requestbin\.com|beeceptor\.com|pipedream\.com)', re.IGNORECASE),
                'private_ips': re.compile(r'(10\.0\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)', re.IGNORECASE)
            })

    def _show_progress(self, step_name: str):
        """Display progress information."""
        self.current_step += 1
        print(f"{Colors.BLUE}[{self.current_step}/{self.total_steps}] 🔍 {step_name}...{Colors.NC}")

    def _verbose_log(self, message: str):
        """Log verbose information if verbose mode enabled."""
        if self.verbose:
            print(f"{Colors.BLUE}  ↳ {message}{Colors.NC}")

    def _discover_files(self, scan_dirs: List[str]) -> Dict[str, List[str]]:
        """Discover files and categorize them for processing."""
        file_categories = {
            'hash_files': [],
            'content_files': [],
            'json_files': [],
            'workflow_files': []
        }

        directories_processed = 0
        for scan_dir in scan_dirs:
            scan_path = Path(scan_dir)
            if not scan_path.exists():
                continue

            directories_processed += 1
            for root, dirs, files in os.walk(scan_path):
                # Skip common irrelevant directories
                dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '.venv', '__pycache__'}]
                directories_processed += len(dirs)

                for file in files:
                    file_path = str(Path(root) / file)
                    suffix = Path(file).suffix.lower()

                    # Categorize files
                    if suffix in {'.js', '.ts', '.json'}:
                        file_categories['hash_files'].append(file_path)
                        file_categories['content_files'].append(file_path)
                        if suffix == '.json':
                            file_categories['json_files'].append(file_path)
                    elif file == 'shai-hulud-workflow.yml':
                        file_categories['workflow_files'].append(file_path)
                    elif suffix in {'.py', '.sh', '.yml', '.yaml'}:
                        file_categories['content_files'].append(file_path)

        self.stats['directories_processed'] = directories_processed
        return file_categories

    def _check_file_hash(self, file_path: str) -> Optional[Finding]:
        """Check single file hash."""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                if file_hash == self.malicious_hash:
                    return Finding(
                        path=file_path,
                        risk_level=RiskLevel.HIGH,
                        category="Malicious File Hash",
                        description=f"File matches known malicious hash: {file_hash}"
                    )
        except Exception:
            pass
        return None

    def _analyze_file_content(self, file_path: str) -> Optional[Finding]:
        """Analyze file content for suspicious patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check for suspicious patterns
            for pattern_name, pattern in self.suspicious_patterns.items():
                if pattern.search(content):
                    risk_level = RiskLevel.HIGH if pattern_name in {'webhook_endpoint', 'malicious_workflow'} else RiskLevel.MEDIUM
                    return Finding(
                        path=file_path,
                        risk_level=risk_level,
                        category="Suspicious Content",
                        description=f"Found {pattern_name} pattern in file"
                    )

        except Exception:
            pass
        return None

    def _analyze_package_json(self, file_path: str) -> Optional[Finding]:
        """Analyze package.json for compromised packages and suspicious patterns."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if not isinstance(data, dict):
                return None

            # Check for compromised packages in dependencies
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                if dep_type in data:
                    for package_name, version in data[dep_type].items():
                        package_version = f"{package_name}:{version}"

                        # Check exact matches
                        if package_version in self.compromised_packages:
                            return Finding(
                                path=file_path,
                                risk_level=RiskLevel.HIGH,
                                category="Compromised Package",
                                description=f"Found compromised package: {package_name}@{version}"
                            )

                        # Check namespace warnings
                        namespace = package_name.split('/')[0] if '/' in package_name else ''
                        if namespace in self.affected_namespaces:
                            return Finding(
                                path=file_path,
                                risk_level=RiskLevel.MEDIUM,
                                category="Suspicious Namespace",
                                description=f"Package from affected namespace: {namespace}"
                            )

            # Check for suspicious postinstall hooks
            scripts = data.get('scripts', {})
            if 'postinstall' in scripts:
                postinstall = scripts['postinstall']
                if self.suspicious_patterns['suspicious_postinstall'].search(postinstall):
                    return Finding(
                        path=file_path,
                        risk_level=RiskLevel.HIGH,
                        category="Suspicious Postinstall Hook",
                        description=f"Suspicious postinstall script: {postinstall}"
                    )

        except Exception:
            pass
        return None

    def scan_directories(self, scan_dirs: List[str]) -> List[Finding]:
        """Main scanning orchestrator using concurrent futures."""
        start_time = time.time()
        print(f"{Colors.BLUE}🔍 Starting Shai-Hulud detection scan...{Colors.NC}")

        if self.verbose:
            print(f"{Colors.BLUE}⚡ Using concurrent processing with {self.max_workers} max workers{Colors.NC}")

        # Discover files
        self._show_progress("Discovering files")
        file_categories = self._discover_files(scan_dirs)

        # Record scan time
        self.stats['scan_time_seconds'] = time.time() - start_time

        if self.verbose:
            self._verbose_log(f"Found {len(file_categories['hash_files'])} files for hash checking")
            self._verbose_log(f"Found {len(file_categories['content_files'])} files for content analysis")
            self._verbose_log(f"Found {len(file_categories['json_files'])} JSON files for package analysis")

        # Create overall progress bar
        total_operations = (
            len(file_categories['hash_files']) +
            len(file_categories['content_files']) +
            len(file_categories['json_files'])
        )

        overall_pbar = tqdm(
            total=total_operations,
            desc="Overall progress",
            unit="files",
            position=1,
            leave=True,
            disable=not self.show_progress or not sys.stderr.isatty()
        ) if total_operations > 0 else None

        # Check file hashes
        self._show_progress("Checking file hashes for known malicious content")
        if file_categories['hash_files']:
            with ThreadPoolExecutor(max_workers=min(16, self.max_workers)) as executor:
                hash_futures = {
                    executor.submit(self._check_file_hash, file_path): file_path
                    for file_path in file_categories['hash_files']
                }

                with tqdm(
                    total=len(file_categories['hash_files']),
                    desc="Hash checking",
                    unit="files",
                    position=0,
                    leave=False,
                    disable=not self.show_progress or not sys.stderr.isatty()
                ) as pbar:
                    for future in as_completed(hash_futures):
                        result = future.result()
                        if result:
                            self.findings.append(result)
                        pbar.update(1)
                        if overall_pbar:
                            overall_pbar.update(1)

        # Analyze content
        self._show_progress("Analyzing file content for suspicious patterns")
        if file_categories['content_files']:
            with ThreadPoolExecutor(max_workers=min(16, self.max_workers)) as executor:
                content_futures = {
                    executor.submit(self._analyze_file_content, file_path): file_path
                    for file_path in file_categories['content_files']
                }

                with tqdm(
                    total=len(file_categories['content_files']),
                    desc="Content analysis",
                    unit="files",
                    position=0,
                    leave=False,
                    disable=not self.show_progress or not sys.stderr.isatty()
                ) as pbar:
                    for future in as_completed(content_futures):
                        result = future.result()
                        if result:
                            self.findings.append(result)
                        pbar.update(1)
                        if overall_pbar:
                            overall_pbar.update(1)

        # Analyze JSON files
        self._show_progress("Analyzing package.json files for compromised packages")
        if file_categories['json_files']:
            with ThreadPoolExecutor(max_workers=min(8, self.max_workers)) as executor:
                json_futures = {
                    executor.submit(self._analyze_package_json, file_path): file_path
                    for file_path in file_categories['json_files']
                }

                with tqdm(
                    total=len(file_categories['json_files']),
                    desc="Package analysis",
                    unit="files",
                    position=0,
                    leave=False,
                    disable=not self.show_progress or not sys.stderr.isatty()
                ) as pbar:
                    for future in as_completed(json_futures):
                        result = future.result()
                        if result:
                            self.findings.append(result)
                        pbar.update(1)
                        if overall_pbar:
                            overall_pbar.update(1)

        # Update stats
        self.stats.update({
            'files_scanned': len(file_categories['hash_files']) + len(file_categories['content_files']),
            'json_files_analyzed': len(file_categories['json_files']),
            'hashes_checked': len(file_categories['hash_files'])
        })

        # Close overall progress bar and ensure it's fully cleared
        if overall_pbar:
            overall_pbar.close()

        # Give progress bars time to fully clear before showing results
        import time as time_module
        time_module.sleep(0.1)

        # Clear any remaining progress bar artifacts
        if sys.stderr.isatty() and self.show_progress:
            print("\033[2K\r", end="", file=sys.stderr)  # Clear current line
            sys.stderr.flush()

        # Record final scan time
        self.stats['scan_time_seconds'] = time.time() - start_time

        self._show_progress("Scan completed")
        return self.findings

    def print_results(self):
        """Print scan results in formatted output."""
        if not self.findings:
            print(f"{Colors.GREEN}✅ No indicators of Shai-Hulud compromise detected.{Colors.NC}")
            print(f"{Colors.GREEN}Your system appears clean from this specific attack.{Colors.NC}")
            return

        # Group findings by risk level
        high_risk = [f for f in self.findings if f.risk_level == RiskLevel.HIGH]
        medium_risk = [f for f in self.findings if f.risk_level == RiskLevel.MEDIUM]

        if high_risk:
            print(f"{Colors.RED}🚨 HIGH RISK: {len(high_risk)} definitive indicators of compromise detected{Colors.NC}")
            # Show all high risk findings - these are critical
            for finding in high_risk:
                print(f"  {finding.path}: {finding.description}")

        if medium_risk:
            print(f"{Colors.YELLOW}⚠️ MEDIUM RISK: {len(medium_risk)} suspicious patterns detected{Colors.NC}")
            # Show all medium risk findings, but with pagination for very large lists
            if self.verbose:
                # In verbose mode, show all findings
                for finding in medium_risk:
                    print(f"  {finding.path}: {finding.description}")
            else:
                # In normal mode, limit to reasonable number
                max_display = 50
                for finding in medium_risk[:max_display]:
                    print(f"  {finding.path}: {finding.description}")

                if len(medium_risk) > max_display:
                    remaining = len(medium_risk) - max_display
                    print(f"  ... and {remaining} more medium risk findings (use --verbose for full list)")

        # Print summary
        total_issues = len(self.findings)
        print(f"\n{Colors.BLUE}📊 Scan Summary:{Colors.NC}")
        print(f"  Scan time: {self.stats['scan_time_seconds']:.3f} seconds")
        print(f"  Directories processed: {self.stats['directories_processed']}")
        print(f"  Files scanned: {self.stats['files_scanned']}")
        print(f"  JSON files analyzed: {self.stats['json_files_analyzed']}")
        print(f"  File hashes checked: {self.stats['hashes_checked']}")
        print(f"  Issues found: {total_issues}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Detect Shai-Hulud NPM supply chain attack indicators",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('directories', nargs='+', help='Directories to scan')
    parser.add_argument('--paranoid', action='store_true',
                       help='Enable additional security checks')
    parser.add_argument('--verbose', action='store_true',
                       help='Show detailed progress information')
    parser.add_argument('--max-workers', type=int, default=None,
                       help='Maximum number of worker threads/processes')
    parser.add_argument('--no-progress', action='store_true',
                       help='Disable progress bars')

    args = parser.parse_args()

    # Validate directories
    valid_dirs = []
    for directory in args.directories:
        if os.path.isdir(directory):
            valid_dirs.append(directory)
        else:
            print(f"{Colors.RED}Error: Directory not found: {directory}{Colors.NC}")

    if not valid_dirs:
        print(f"{Colors.RED}Error: No valid directories to scan{Colors.NC}")
        sys.exit(1)

    # Create detector and run scan
    detector = ShaiHuludDetector(
        verbose=args.verbose,
        paranoid=args.paranoid,
        max_workers=args.max_workers,
        show_progress=not args.no_progress
    )

    try:
        findings = detector.scan_directories(valid_dirs)
        detector.print_results()

        # Exit with appropriate code
        high_risk_count = len([f for f in findings if f.risk_level == RiskLevel.HIGH])
        sys.exit(1 if high_risk_count > 0 else 0)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user{Colors.NC}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}Error during scan: {e}{Colors.NC}")
        sys.exit(1)


if __name__ == "__main__":
    main()