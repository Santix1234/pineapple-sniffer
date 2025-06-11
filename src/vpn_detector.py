import subprocess
import re
import platform
import typing

class VPNDetector:
    """
    A utility class for detecting active VPN connections across different platforms.
    
    This class provides methods to identify if a VPN is currently active on the system
    by checking network interfaces, routes, and connection details.
    """
    
    @staticmethod
    def is_vpn_active() -> bool:
        """
        Detect if a VPN is currently active on the system.
        
        Returns:
            bool: True if a VPN connection is detected, False otherwise.
        
        Raises:
            RuntimeError: If unable to perform VPN detection on the current platform.
        """
        system = platform.system().lower()
        
        try:
            if system == 'darwin':  # macOS
                return VPNDetector._check_vpn_macos()
            elif system == 'linux':
                return VPNDetector._check_vpn_linux()
            else:
                raise RuntimeError(f"VPN detection not supported on {system}")
        except Exception as e:
            # Log the error or handle it as needed
            return False
    
    @staticmethod
    def _check_vpn_macos() -> bool:
        """
        Check for VPN connections on macOS.
        
        Returns:
            bool: True if a VPN connection is detected, False otherwise.
        """
        try:
            # Check network service types
            result = subprocess.run(['scutil', '--nc', 'list'], 
                                    capture_output=True, 
                                    text=True, 
                                    timeout=5)
            
            # Look for active VPN connections in the output
            return bool(re.search(r'(Connected|Connecting)', result.stdout, re.IGNORECASE))
        except Exception:
            return False
    
    @staticmethod
    def _check_vpn_linux() -> bool:
        """
        Check for VPN connections on Linux systems.
        
        Returns:
            bool: True if a VPN connection is detected, False otherwise.
        """
        try:
            # Check network interfaces for typical VPN interface names
            vpn_interfaces = ['tun', 'tap', 'ppp', 'wg']
            
            # Get network interfaces
            result = subprocess.run(['ip', 'link'], 
                                    capture_output=True, 
                                    text=True, 
                                    timeout=5)
            
            # Check if any known VPN interface is present and up
            return any(
                interface in result.stdout.lower() and 'state up' in result.stdout.lower()
                for interface in vpn_interfaces
            )
        except Exception:
            return False

def detect_vpn() -> bool:
    """
    Convenience function to check if a VPN is active.
    
    Returns:
        bool: True if a VPN connection is detected, False otherwise.
    """
    return VPNDetector.is_vpn_active()