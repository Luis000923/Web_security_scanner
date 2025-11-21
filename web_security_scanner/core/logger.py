"""
Advanced logging system for Web Security Scanner
Provides structured logging with rotation and multiple handlers
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional
from colorama import Fore, Style


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for console output"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }
    
    def format(self, record):
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


def setup_logger(
    name: str = 'WebSecurityScanner',
    level: str = 'INFO',
    log_file: Optional[str] = None,
    max_size: int = 10485760,  # 10MB
    backup_count: int = 5,
    log_format: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
) -> logging.Logger:
    """
    Setup and configure logger with file and console handlers
    
    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        max_size: Maximum log file size before rotation
        backup_count: Number of backup files to keep
        log_format: Log message format
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))
    console_formatter = ColoredFormatter(log_format)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation (if log_file specified)
    if log_file:
        # Create logs directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(getattr(logging, level.upper()))
        file_formatter = logging.Formatter(log_format)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


class ScanLogger:
    """Wrapper class for structured logging during scans"""
    
    def __init__(self, logger: logging.Logger, verbose: bool = False):
        self.logger = logger
        self.verbose = verbose
        self.scan_stats = {
            'errors': 0,
            'warnings': 0,
            'vulnerabilities': 0,
            'requests': 0
        }
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        if self.verbose:
            self.logger.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.scan_stats['warnings'] += 1
        self.logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self.scan_stats['errors'] += 1
        self.logger.error(message, extra=kwargs)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.scan_stats['errors'] += 1
        self.logger.critical(message, extra=kwargs)
    
    def vulnerability(self, vuln_type: str, url: str, details: dict):
        """Log vulnerability finding"""
        self.scan_stats['vulnerabilities'] += 1
        self.logger.warning(
            f"Vulnerability found: {vuln_type}",
            extra={
                'vuln_type': vuln_type,
                'url': url,
                'details': details
            }
        )
    
    def request(self, method: str, url: str, status_code: int = None):
        """Log HTTP request"""
        self.scan_stats['requests'] += 1
        if self.verbose:
            msg = f"Request: {method} {url}"
            if status_code:
                msg += f" - Status: {status_code}"
            self.logger.debug(msg)
    
    def get_stats(self) -> dict:
        """Get current scan statistics"""
        return self.scan_stats.copy()
    
    def reset_stats(self):
        """Reset scan statistics"""
        self.scan_stats = {
            'errors': 0,
            'warnings': 0,
            'vulnerabilities': 0,
            'requests': 0
        }
