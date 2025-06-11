import subprocess
import re
import platform
from typing import Dict, Optional, List

class VPNDetector:
    """
    A comprehensive VPN detection utility for multiple operating systems.
    
    Supports detection of active VPN connections across different platforms.
    """
    
    @staticmethod
    def detect_vpn_connection() -> Dict[str, Optional[str]]:
        """
        Detect active VPN connection details.
        
        Returns:
            Dict containing VPN connection information or None if no VPN detected.
        """
        os_name = platform.system().lower()
        
        try:
            if os_name == 'darwin':  # macOS
                return VPNDetector._detect_macos_vpn()
            elif os_name == 'linux':
                return VPNDetector._detect_linux_vpn()
            else:
                return {
                    'status': 'unsupported_os',
                    'platform': os_name
                }
        except Exception as e:
            return {
                'status': 'detection_error',
                'error': str(e)
            }
    
    @staticmethod
    def _detect_macos_vpn() -> Dict[str, Optional[str]]:
        """
        Detect VPN connections on macOS.
        
        Returns:
            Dict of VPN connection details.
        """
        try:
            # Check network interface for VPN
            result = subprocess.run(['networksetup', '-listnetworkserviceorder'], 
                                    capture_output=True, text=True, timeout=5)
            vpn_interfaces = re.findall(r'VPN|L2TP|PPTP', result.stdout)
            
            if vpn_interfaces:
                return {
                    'status': 'connected',
                    'type': vpn_interfaces[0],
                    'platform': 'macOS'
                }
            return {'status': 'not_connected'}
        except Exception as e:
            return {
                'status': 'detection_error', 
                'platform': 'macOS',
                'error': str(e)
            }
    
    @staticmethod
    def _detect_linux_vpn() -> Dict[str, Optional[str]]:
        """
        Detect VPN connections on Linux.
        
        Returns:
            Dict of VPN connection details.
        """
        try:
            # Check network interfaces for typical VPN patterns
            result = subprocess.run(['ip', 'addr'], 
                                    capture_output=True, text=True, timeout=5)
            
            vpn_patterns = ['tun', 'tap', 'ppp', 'wg']
            for pattern in vpn_patterns:
                if pattern in result.stdout:
                    return {
                        'status': 'connected',
                        'type': pattern,
                        'platform': 'Linux'
                    }
            
            return {'status': 'not_connected'}
        except Exception as e:
            return {
                'status': 'detection_error', 
                'platform': 'Linux',
                'error': str(e)
            }