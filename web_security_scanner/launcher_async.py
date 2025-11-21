import tkinter as tk
import logging
import sys
import os
import yaml
from pathlib import Path

# Ensure the package is in path if running directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from web_security_scanner.web_security_scanner_async import WebSecurityScanner
from web_security_scanner.gui.controllers.scan_controller import ScanController
from web_security_scanner.gui.main_window import MainWindow
from web_security_scanner.utils.i18n import i18n

def load_config():
    """Load configuration from config.yaml"""
    config_path = Path("config.yaml")
    if not config_path.exists():
        # Fallback to default if not found in root
        config_path = Path(__file__).parent / "config.yaml"
        
    if config_path.exists():
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    return {}

def main():
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Load Config
    config = load_config()
    
    # Initialize I18n
    lang_file = Path(__file__).parent / "languages.yaml"
    i18n.load_languages(str(lang_file))
    i18n.set_language(config.get('language', 'en'))
    
    root = tk.Tk()
    
    # Initialize scanner with config
    # Map legacy config to new async config
    legacy_scanner_config = config.get('scanner', {})
    
    # Calculate rate limit (legacy is req/s, new is seconds/req)
    rate_limit_req_per_sec = legacy_scanner_config.get('rate_limit', 10)
    rate_limit_interval = 1.0 / rate_limit_req_per_sec if rate_limit_req_per_sec > 0 else 0.0

    core_config = {
        'max_concurrency': legacy_scanner_config.get('threads', 50),
        'timeout': legacy_scanner_config.get('timeout', 10),
        'user_agent': legacy_scanner_config.get('user_agent', "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
        'rate_limit': rate_limit_interval,
        'headers': {}
    }

    scanner_config = {
        'core': core_config,
        'testers': config.get('vulnerabilities', {})
    }
    
    scanner = WebSecurityScanner(scanner_config)
    controller = ScanController(scanner)
    app = MainWindow(root, controller)
    
    root.mainloop()

if __name__ == "__main__":
    main()
