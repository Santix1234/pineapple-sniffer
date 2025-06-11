#!/usr/bin/env python3
"""
WiFi Pineapple & Network Security Detector
==========================================

A comprehensive security test for detecting WiFi Pineapple attacks, 
man-in-the-middle attacks, and system vulnerabilities.

Usage: python3 pineapple_detector.py [--quick] [--verbose]

Based on security analysis methodology that uses established tools
to minimize false positives while detecting real threats.
"""

import subprocess
import json
import datetime
import sys
import os
import argparse
from typing import Dict, List, Optional, Tuple, Any

class PineappleDetector:
    # ... [Previous code remains the same] ...

    def validate_vpn_connection_details(self, vpn_details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate VPN connection details for security and configuration.
        
        Args:
            vpn_details (Dict[str, Any]): Dictionary containing VPN connection parameters
        
        Returns:
            Dict[str, Any]: Validation results including validity status and detected issues
        """
        # Predefined security configurations
        SECURE_PROTOCOLS = ['OpenVPN', 'WireGuard', 'IPSec']
        WEAK_PROTOCOLS = ['PPTP', 'L2TP']
        
        STRONG_ENCRYPTION = ['AES-256-GCM', 'AES-256-CBC', 'ChaCha20']
        WEAK_ENCRYPTION = ['MPPE-40', 'MPPE-128', 'DES']
        
        STRONG_AUTH = ['SHA-256', 'SHA-384', 'SHA-512']
        WEAK_AUTH = ['MS-CHAPv2', 'MD5', 'CHAP']
        
        # Validation result structure
        result = {
            'is_valid': True,
            'issues': [],
            'encryption_strength': 'weak',
            'protocol_status': 'unknown'
        }
        
        # Check for empty details
        if not vpn_details:
            result['is_valid'] = False
            result['issues'].append('No VPN connection details provided')
            return result
        
        # Protocol Validation
        protocol = vpn_details.get('protocol', '').strip()
        if protocol in WEAK_PROTOCOLS:
            result['is_valid'] = False
            result['issues'].append(f'Weak VPN protocol: {protocol}')
            result['protocol_status'] = 'weak'
        elif protocol in SECURE_PROTOCOLS:
            result['protocol_status'] = 'secure'
        
        # Encryption Validation
        encryption = vpn_details.get('encryption', '').strip()
        if encryption in STRONG_ENCRYPTION:
            result['encryption_strength'] = 'strong'
        elif encryption in WEAK_ENCRYPTION:
            result['is_valid'] = False
            result['issues'].append(f'Weak encryption: {encryption}')
            result['encryption_strength'] = 'weak'
        
        # Authentication Validation
        auth = vpn_details.get('authentication', '').strip()
        if auth in WEAK_AUTH:
            result['is_valid'] = False
            result['issues'].append(f'Weak authentication method: {auth}')
        elif auth in STRONG_AUTH:
            result['authentication_status'] = 'secure'
        
        # Port Validation
        port = vpn_details.get('port')
        if port is None or not isinstance(port, int) or port <= 0 or port > 65535:
            result['is_valid'] = False
            result['issues'].append(f'Invalid port number: {port}')
        
        # Server Validation
        server = vpn_details.get('server', '').strip()
        if not server or len(server) < 3:
            result['is_valid'] = False
            result['issues'].append('Invalid or missing VPN server address')
        
        return result

# ... [Rest of the previous code remains unchanged] ...