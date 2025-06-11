import pytest
from unittest.mock import patch
from src.vpn.detector import VPNDetector

class TestVPNDetector:
    @patch('platform.system', return_value='Darwin')
    @patch('subprocess.run')
    def test_macos_vpn_detection_connected(self, mock_run, mock_platform):
        """
        Test VPN detection on macOS when a VPN is connected.
        """
        mock_run.return_value.stdout = "VPN Service: (Hardware Port: VPN (L2TP), Device: ppp0)"
        
        result = VPNDetector.detect_vpn_connection()
        
        assert result['status'] == 'connected'
        assert result['platform'] == 'macOS'
        assert 'type' in result
    
    @patch('platform.system', return_value='Darwin')
    @patch('subprocess.run')
    def test_macos_vpn_detection_not_connected(self, mock_run, mock_platform):
        """
        Test VPN detection on macOS when no VPN is connected.
        """
        mock_run.return_value.stdout = "No VPN interfaces"
        
        result = VPNDetector.detect_vpn_connection()
        
        assert result['status'] == 'not_connected'
    
    @patch('platform.system', return_value='Linux')
    @patch('subprocess.run')
    def test_linux_vpn_detection_connected(self, mock_run, mock_platform):
        """
        Test VPN detection on Linux when a VPN is connected.
        """
        mock_run.return_value.stdout = "tun0: flags=..."
        
        result = VPNDetector.detect_vpn_connection()
        
        assert result['status'] == 'connected'
        assert result['platform'] == 'Linux'
        assert result['type'] == 'tun'
    
    @patch('platform.system', return_value='Linux')
    @patch('subprocess.run')
    def test_linux_vpn_detection_not_connected(self, mock_run, mock_platform):
        """
        Test VPN detection on Linux when no VPN is connected.
        """
        mock_run.return_value.stdout = "No special interfaces"
        
        result = VPNDetector.detect_vpn_connection()
        
        assert result['status'] == 'not_connected'
    
    @patch('platform.system', return_value='Windows')
    def test_unsupported_os(self, mock_platform):
        """
        Test detection on unsupported operating system.
        """
        result = VPNDetector.detect_vpn_connection()
        
        assert result['status'] == 'unsupported_os'
        assert result['platform'] == 'windows'