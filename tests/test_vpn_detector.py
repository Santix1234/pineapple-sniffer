import pytest
from src.vpn_detector import PineappleDetector

def test_validate_vpn_connection():
    """
    Test the validate_vpn_connection method.
    """
    detector = PineappleDetector()
    result = detector.validate_vpn_connection()
    
    # Check that the result contains expected keys
    assert 'is_connected' in result
    assert 'ip_address_valid' in result
    assert 'dns_valid' in result
    assert 'protocol_secure' in result
    assert 'connection_details' in result

def test_validate_ip_address():
    """
    Test IP address validation method.
    """
    detector = PineappleDetector()
    
    # Test valid IP addresses
    assert detector._validate_ip_address('10.0.0.1') == True
    assert detector._validate_ip_address('192.168.1.1') == True
    
    # Test invalid IP addresses
    assert detector._validate_ip_address('999.999.999.999') == False
    assert detector._validate_ip_address('invalid_ip') == False

def test_validate_dns_servers():
    """
    Test DNS server validation method.
    """
    detector = PineappleDetector()
    
    # Test valid DNS server lists
    assert detector._validate_dns_servers(['8.8.8.8', '1.1.1.1']) == True
    
    # Test invalid DNS server lists
    assert detector._validate_dns_servers([]) == False
    assert detector._validate_dns_servers(['invalid_ip']) == False

def test_validate_vpn_protocol():
    """
    Test VPN protocol validation method.
    """
    detector = PineappleDetector()
    
    # Test secure protocols
    assert detector._validate_vpn_protocol('OpenVPN') == True
    assert detector._validate_vpn_protocol('WireGuard') == True
    assert detector._validate_vpn_protocol('IPSec') == True
    
    # Test insecure protocols
    assert detector._validate_vpn_protocol('PPTP') == False
    assert detector._validate_vpn_protocol('L2TP') == False