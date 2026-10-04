#!/usr/bin/env python3
"""
Honeypot Event Ingester for Digital Twin

Reads logs from local honeypots and ingests them into the digital twin
via the /events/ingest API endpoint.

Usage:
    python scripts/ingest_honeypot_logs.py --network-id <id> --log-dir /var/log/honeypots
"""

import json
import argparse
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any, Generator
import requests
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HoneypotEventParser:
    """Parse honeypot logs and convert to threat events"""

    def __init__(self, twin_url: str = "http://localhost:8000"):
        self.twin_url = twin_url.rstrip('/')
        self.session = requests.Session()

    def parse_cowrie_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse Cowrie JSON log line"""
        try:
            log_entry = json.loads(log_line)
        except json.JSONDecodeError:
            return None

        event_type = log_entry.get('eventid', '')
        timestamp = log_entry.get('timestamp', datetime.utcnow().isoformat())

        # Map Cowrie events to MITRE ATT&CK techniques
        technique_mapping = {
            'cowrie.command.input': 'T1059',      # Command and Scripting Interpreter
            'cowrie.login.failed': 'T1110',       # Brute Force
            'cowrie.login.success': 'T1078',      # Valid Accounts
            'cowrie.session.file_download': 'T1105',  # Ingress Tool Transfer
            'cowrie.session.connect': 'T1571',    # Non-Standard Port
        }

        technique = technique_mapping.get(event_type, 'T1021')  # Default: Remote Services

        event = {
            'timestamp': timestamp,
            'source_ip': log_entry.get('src_ip', 'unknown'),
            'source_port': log_entry.get('src_port', 0),
            'target_asset': 'HONEYPOT-SSH-01',
            'target_port': 22,
            'protocol': 'ssh',
            'event_type': event_type,
            'technique': technique,
            'severity': 'medium',
            'payload': {
                'username': log_entry.get('username', ''),
                'password': log_entry.get('password', ''),
                'command': log_entry.get('input', ''),
                'session_id': log_entry.get('session', ''),
            }
        }

        return event

    def parse_dionaea_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse Dionaea log line"""
        # Dionaea logs are typically plain text; parse key patterns
        if not log_line.strip():
            return None

        # Example: "2024-01-15 10:23:45 [FTP] LOGIN FAILED: user=admin from 203.0.113.45"
        timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', log_line)
        if not timestamp_match:
            return None

        timestamp = timestamp_match.group(1)

        # Detect protocol
        if '[FTP]' in log_line:
            protocol, port, technique = 'ftp', 21, 'T1040'  # Network Sniffing as placeholder
        elif '[SMB]' in log_line:
            protocol, port, technique = 'smb', 445, 'T1021'  # Remote Services
        elif '[MySQL]' in log_line:
            protocol, port, technique = 'mysql', 3306, 'T1110'  # Brute Force
        else:
            protocol, port, technique = 'unknown', 0, 'T1021'

        # Extract source IP
        ip_match = re.search(r'from (\S+)', log_line)
        source_ip = ip_match.group(1) if ip_match else 'unknown'

        event = {
            'timestamp': timestamp,
            'source_ip': source_ip,
            'target_asset': f'HONEYPOT-{protocol.upper()}-01',
            'target_port': port,
            'protocol': protocol,
            'event_type': 'connection_attempt',
            'technique': technique,
            'severity': 'medium',
            'payload': {'raw_log': log_line}
        }

        return event

    def parse_glastopf_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse Glastopf web honeypot log"""
        try:
            log_entry = json.loads(log_line)
        except json.JSONDecodeError:
            return None

        event = {
            'timestamp': log_entry.get('timestamp', datetime.utcnow().isoformat()),
            'source_ip': log_entry.get('source_ip', 'unknown'),
            'target_asset': 'HONEYPOT-WEB-01',
            'target_port': 80,
            'protocol': 'http',
            'event_type': log_entry.get('event_type', 'web_request'),
            'technique': 'T1190',  # Exploit Public-Facing Application
            'severity': log_entry.get('severity', 'medium'),
            'payload': {
                'method': log_entry.get('method', 'GET'),
                'path': log_entry.get('path', '/'),
                'user_agent': log_entry.get('user_agent', ''),
                'payload': log_entry.get('payload', ''),
            }
        }

        return event

    def ingest_event(self, network_id: str, event: Dict[str, Any]) -> bool:
        """Send event to digital twin"""
        url = f"{self.twin_url}/api/v1/networks/{network_id}/events/ingest"
        
        try:
            response = self.session.post(url, json=event, timeout=5)
            if response.status_code == 202:  # Accepted
                logger.info(f"✓ Ingested: {event['source_ip']} → {event['target_asset']} ({event['technique']})")
                return True
            else:
                logger.warning(f"✗ Failed to ingest event: {response.status_code} {response.text}")
                return False
        except requests.RequestException as e:
            logger.error(f"Connection error: {e}")
            return False

    def read_logs(self, log_dir: Path, pattern: str) -> Generator[str, None, None]:
        """Yield lines from honeypot logs matching pattern"""
        log_dir = Path(log_dir)
        if not log_dir.exists():
            logger.warning(f"Log directory not found: {log_dir}")
            return

        for log_file in log_dir.rglob(pattern):
            if log_file.is_file():
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            yield line
                except IOError as e:
                    logger.error(f"Error reading {log_file}: {e}")

    def process_honeypot_logs(self, network_id: str, log_dir: Path) -> None:
        """Read all honeypot logs and ingest events"""
        stats = {'cowrie': 0, 'dionaea': 0, 'glastopf': 0, 'errors': 0}

        # Process Cowrie logs
        logger.info("Processing Cowrie (SSH) logs...")
        for line in self.read_logs(log_dir / 'cowrie', '*.json'):
            event = self.parse_cowrie_log(line)
            if event:
                if self.ingest_event(network_id, event):
                    stats['cowrie'] += 1
                else:
                    stats['errors'] += 1

        # Process Dionaea logs
        logger.info("Processing Dionaea (multi-protocol) logs...")
        for line in self.read_logs(log_dir / 'dionaea', '*.log'):
            event = self.parse_dionaea_log(line)
            if event:
                if self.ingest_event(network_id, event):
                    stats['dionaea'] += 1
                else:
                    stats['errors'] += 1

        # Process Glastopf logs
        logger.info("Processing Glastopf (web) logs...")
        for line in self.read_logs(log_dir / 'glastopf', '*.log'):
            event = self.parse_glastopf_log(line)
            if event:
                if self.ingest_event(network_id, event):
                    stats['glastopf'] += 1
                else:
                    stats['errors'] += 1

        # Summary
        logger.info("=" * 60)
        logger.info("Ingestion Summary")
        logger.info("=" * 60)
        logger.info(f"Cowrie events:    {stats['cowrie']}")
        logger.info(f"Dionaea events:   {stats['dionaea']}")
        logger.info(f"Glastopf events:  {stats['glastopf']}")
        logger.info(f"Errors:           {stats['errors']}")
        logger.info(f"Total:            {sum(stats.values()) - stats['errors']}")


def main():
    parser = argparse.ArgumentParser(description='Ingest honeypot logs into digital twin')
    parser.add_argument('--network-id', required=True, help='Network ID in the digital twin')
    parser.add_argument('--log-dir', default='/var/log/honeypots', help='Honeypot log directory')
    parser.add_argument('--twin-url', default='http://localhost:8000', help='Digital twin API URL')
    parser.add_argument('--watch', action='store_true', help='Watch log directory for changes (tail mode)')
    parser.add_argument('--interval', type=int, default=5, help='Poll interval in seconds (for watch mode)')

    args = parser.parse_args()

    ingester = HoneypotEventParser(twin_url=args.twin_url)

    if args.watch:
        logger.info(f"Watching {args.log_dir} for new events (interval: {args.interval}s)")
        logger.info("Press Ctrl+C to stop")
        try:
            while True:
                ingester.process_honeypot_logs(args.network_id, Path(args.log_dir))
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("Stopped by user")
    else:
        ingester.process_honeypot_logs(args.network_id, Path(args.log_dir))


if __name__ == '__main__':
    main()
