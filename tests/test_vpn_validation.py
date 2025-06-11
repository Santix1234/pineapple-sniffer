import pytest
import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pineapple_detector import PineappleDetector

def test_validate_vpn_connection_details():
    detector = PineappleDetector()
    
    # Mock VPN connection details
    vpn_details = {
        'protocol': 'OpenVPN',
        'server': 'vpn.example.com',
        'port': 1194,
        'encryption': 'AES-256-GCM',
        'authentication': 'SHA-256'
    }
    
    result = detector.validate_vpn_connection_details(vpn_details)
    
    assert result['is_valid'], f"VPN connection validation failed: {result.get('issues', [])}"
    assert result['encryption_strength'] == 'strong', "Encryption strength should be strong"

def test_validate_vpn_connection_with_weak_PARAMETERS():
    detector = PineappleDetector()
    
    # Weak VPN configuration
    weak_vpn_details = {
        'protocol': 'PPTP',  # Known weak protocol
        'server': 'unknown.vpn.com',
        'port': 1723,
        'encryption': 'MPPE-40',  # Weak encryption
        'authentication': 'MS-CHAPv2'  # Weak authentication
    }
    
    result = detector.validate_vpn_connection_details(weak_vpn_details)
    
    assert not result['is_valid'], "Weak VPN configuration should not pass validation"
    assert len(result.get('issues', [])) > 0, "Weak VPN configuration should have identified issues"

def test_validate_vpn_connection_empty_details():
    detector = PineappleDetector()
    
    result = detector.validate_vpn_connection_details({})
    
    assert not result['is_valid'], "Empty VPN details should not pass validation"
    assert 'No VPN connection details provided' in result.get('issues', [])