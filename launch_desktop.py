#!/usr/bin/env python3
"""
SQL Injection Scanner - Desktop Version Launcher
Simple launcher script for the PyQt5 GUI application
"""

import sys
import os
import subprocess
import importlib.util

def check_dependencies():
    """Check if required dependencies are installed"""
    required_packages = ['PyQt5', 'requests']
    missing_packages = []
    
    for package in required_packages:
        spec = importlib.util.find_spec(package)
        if spec is None:
            missing_packages.append(package)
    
    return missing_packages

def install_dependencies(packages):
    """Install missing dependencies"""
    print(f"Installing missing dependencies: {', '.join(packages)}")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + packages)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install dependencies: {e}")
        return False

def main():
    """Main launcher function"""
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║           SQL Injection Scanner - Desktop Version            ║
    ║                          Launcher                            ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Check dependencies
    print("[*] Checking dependencies...")
    missing = check_dependencies()
    
    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}")
        response = input("Would you like to install them? (y/n): ").lower()
        
        if response == 'y':
            if not install_dependencies(missing):
                print("[!] Failed to install dependencies. Please install manually:")
                print(f"    pip install {' '.join(missing)}")
                sys.exit(1)
        else:
            print("[!] Cannot continue without required dependencies.")
            sys.exit(1)
    
    print("[+] All dependencies are available")
    
    # Check if desktop_scanner.py exists
    if not os.path.exists('desktop_scanner.py'):
        print("[!] desktop_scanner.py not found in current directory")
        sys.exit(1)
    
    # Launch the desktop application
    print("[*] Launching SQL Injection Scanner GUI...")
    try:
        from desktop_scanner import main as desktop_main
        desktop_main()
    except ImportError as e:
        print(f"[!] Failed to import desktop scanner: {e}")
        print("[*] Trying direct execution...")
        try:
            subprocess.run([sys.executable, 'desktop_scanner.py'])
        except Exception as e:
            print(f"[!] Failed to launch desktop scanner: {e}")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Error launching desktop scanner: {e}")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Launcher interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)