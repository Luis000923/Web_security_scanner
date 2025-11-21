#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Instalador Interactivo - Web Security Scanner v4.0
===================================================

Script de instalación que permite al usuario:
1. Seleccionar idioma de la aplicación (inglés o español)
2. Crear archivo de configuración personalizado
3. Instalar dependencias automáticamente
4. Verificar la instalación

Uso:
    python install.py

Conexiones:
-----------
- Crea: config.yaml (archivo de configuración)
- Ejecuta: pip install -r requirements.txt
- Valida: Importa módulos del core para verificar instalación
"""

import os
import sys
import subprocess
import yaml
from pathlib import Path
from typing import Dict, Any

# Colores para terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_colored(text: str, color: str = Colors.END):
    """Imprime texto en color."""
    print(f"{color}{text}{Colors.END}")

def print_banner():
    """Muestra el banner de instalación."""
    banner = """
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║        🔒 WEB SECURITY SCANNER v4.0 - INSTALACIÓN 🔒            ║
    ║                                                                  ║
    ║                  Professional Security Tool                      ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    print_colored(banner, Colors.CYAN + Colors.BOLD)

def select_language() -> str:
    """
    Permite al usuario seleccionar el idioma.
    
    Returns:
        Código del idioma seleccionado ('en' o 'es')
    """
    print_colored("\n" + "="*70, Colors.BLUE)
    print_colored("  SELECT YOUR LANGUAGE / SELECCIONE SU IDIOMA", Colors.BOLD)
    print_colored("="*70, Colors.BLUE)
    
    print("\n  1. 🇬🇧 English")
    print("  2. 🇪🇸 Español")
    
    while True:
        choice = input(f"\n  {Colors.YELLOW}➤ Select option (1 or 2): {Colors.END}").strip()
        
        if choice == '1':
            print_colored("\n  ✓ Language set to: English", Colors.GREEN)
            return 'en'
        elif choice == '2':
            print_colored("\n  ✓ Idioma establecido: Español", Colors.GREEN)
            return 'es'
        else:
            print_colored("  ✗ Invalid option. Please select 1 or 2.", Colors.RED)

def get_translations(language: str) -> Dict[str, str]:
    """
    Obtiene las traducciones para el idioma seleccionado.
    
    Args:
        language: Código del idioma
        
    Returns:
        Diccionario con traducciones
    """
    translations = {
        'en': {
            'creating_config': 'Creating configuration file...',
            'config_created': 'Configuration file created successfully!',
            'installing_deps': 'Installing Python dependencies...',
            'this_may_take': 'This may take a few minutes...',
            'deps_installed': 'Dependencies installed successfully!',
            'deps_error': 'Error installing dependencies',
            'verifying': 'Verifying installation...',
            'verify_success': 'Installation verified successfully!',
            'verify_error': 'Verification failed',
            'install_complete': 'Installation completed!',
            'quick_start': 'Quick Start',
            'test_command': 'Test the installation:',
            'scan_command': 'Run a basic scan:',
            'full_scan': 'Run a comprehensive scan:',
            'documentation': 'Documentation',
            'enjoy': 'Enjoy scanning! 🔒',
            'profile_prompt': 'Select default scan profile:',
            'profile_quick': 'Quick - Fast scan (CI/CD)',
            'profile_normal': 'Normal - Balanced scan',
            'profile_deep': 'Deep - Comprehensive scan',
            'profile_stealth': 'Stealth - Evasive scan',
            'threads_prompt': 'Number of threads (1-50):',
            'timeout_prompt': 'Request timeout in seconds (10-120):',
        },
        'es': {
            'creating_config': 'Creando archivo de configuración...',
            'config_created': '¡Archivo de configuración creado exitosamente!',
            'installing_deps': 'Instalando dependencias de Python...',
            'this_may_take': 'Esto puede tomar unos minutos...',
            'deps_installed': '¡Dependencias instaladas exitosamente!',
            'deps_error': 'Error al instalar dependencias',
            'verifying': 'Verificando instalación...',
            'verify_success': '¡Instalación verificada exitosamente!',
            'verify_error': 'Falló la verificación',
            'install_complete': '¡Instalación completada!',
            'quick_start': 'Inicio Rápido',
            'test_command': 'Probar la instalación:',
            'scan_command': 'Ejecutar escaneo básico:',
            'full_scan': 'Ejecutar escaneo completo:',
            'documentation': 'Documentación',
            'enjoy': '¡Disfruta escaneando! 🔒',
            'profile_prompt': 'Seleccione perfil de escaneo predeterminado:',
            'profile_quick': 'Quick - Escaneo rápido (CI/CD)',
            'profile_normal': 'Normal - Escaneo balanceado',
            'profile_deep': 'Deep - Escaneo exhaustivo',
            'profile_stealth': 'Stealth - Escaneo evasivo',
            'threads_prompt': 'Número de hilos (1-50):',
            'timeout_prompt': 'Timeout de petición en segundos (10-120):',
        }
    }
    return translations.get(language, translations['en'])

def select_profile(t: Dict[str, str]) -> str:
    """
    Permite al usuario seleccionar un perfil de escaneo.
    
    Args:
        t: Diccionario de traducciones
        
    Returns:
        Nombre del perfil seleccionado
    """
    print(f"\n  {t['profile_prompt']}")
    print(f"  1. {t['profile_quick']}")
    print(f"  2. {t['profile_normal']}")
    print(f"  3. {t['profile_deep']}")
    print(f"  4. {t['profile_stealth']}")
    
    while True:
        choice = input(f"\n  {Colors.YELLOW}➤ Option (1-4) [2]: {Colors.END}").strip() or '2'
        
        profiles = {
            '1': 'quick',
            '2': 'normal',
            '3': 'deep',
            '4': 'stealth'
        }
        
        if choice in profiles:
            return profiles[choice]
        else:
            print_colored("  ✗ Invalid option.", Colors.RED)

def get_custom_settings(t: Dict[str, str]) -> Dict[str, Any]:
    """
    Obtiene configuraciones personalizadas del usuario.
    
    Args:
        t: Diccionario de traducciones
        
    Returns:
        Diccionario con configuraciones
    """
    settings = {}
    
    # Threads
    while True:
        threads = input(f"\n  {t['threads_prompt']} [10]: ").strip() or '10'
        try:
            threads_num = int(threads)
            if 1 <= threads_num <= 50:
                settings['threads'] = threads_num
                break
            else:
                print_colored("  ✗ Value must be between 1 and 50.", Colors.RED)
        except ValueError:
            print_colored("  ✗ Please enter a valid number.", Colors.RED)
    
    # Timeout
    while True:
        timeout = input(f"  {t['timeout_prompt']} [35]: ").strip() or '35'
        try:
            timeout_num = int(timeout)
            if 10 <= timeout_num <= 120:
                settings['timeout'] = timeout_num
                break
            else:
                print_colored("  ✗ Value must be between 10 and 120.", Colors.RED)
        except ValueError:
            print_colored("  ✗ Please enter a valid number.", Colors.RED)
    
    return settings

def create_config(language: str, profile: str, custom_settings: Dict[str, Any]):
    """
    Crea el archivo de configuración config.yaml.
    
    Args:
        language: Código del idioma
        profile: Perfil de escaneo seleccionado
        custom_settings: Configuraciones personalizadas
    """
    config = {
        'language': language,
        'scanner': {
            'threads': custom_settings.get('threads', 10),
            'timeout': custom_settings.get('timeout', 35),
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'verify_ssl': True,
            'follow_redirects': True,
            'max_redirects': 5,
            'rate_limit': 10,
        },
        'cache': {
            'enabled': True,
            'ttl': 3600,
        },
        'vulnerabilities': {
            'sql_injection': {'enabled': True, 'max_payloads': 50},
            'xss': {'enabled': True, 'max_payloads': 50},
            'nosql_injection': {'enabled': True, 'max_payloads': 30},
            'ssrf': {'enabled': True, 'max_payloads': 40},
            'command_injection': {'enabled': True, 'max_payloads': 45},
            'path_traversal': {'enabled': True, 'max_payloads': 50},
            'xxe': {'enabled': True, 'max_payloads': 14},
            'csrf': {'enabled': True},
            'idor': {'enabled': True, 'test_count': 5},
            'open_redirect': {'enabled': True, 'max_payloads': 20},
        },
        'technology_detection': {
            'enabled': True,
            'detect_cms': True,
            'detect_frameworks': True,
            'detect_server': True,
            'detect_waf': True,
            'detect_cdn': True,
        },
        'logging': {
            'level': 'INFO',
            'file': 'logs/scanner.log',
            'max_size': 10485760,
            'backup_count': 5,
            'console_output': True,
            'colored_output': True,
        },
        'profiles': {
            'quick': {
                'threads': 20,
                'timeout': 10,
                'rate_limit': 20,
                'max_payloads_per_vuln': 10,
            },
            'normal': {
                'threads': 10,
                'timeout': 35,
                'rate_limit': 10,
                'max_payloads_per_vuln': 50,
            },
            'deep': {
                'threads': 5,
                'timeout': 60,
                'rate_limit': 5,
                'max_payloads_per_vuln': 100,
            },
            'stealth': {
                'threads': 2,
                'timeout': 45,
                'rate_limit': 2,
                'max_payloads_per_vuln': 30,
            },
        },
        'default_profile': profile,
    }
    
    config_path = Path('config.yaml')
    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

def install_dependencies(t: Dict[str, str]) -> bool:
    """
    Instala las dependencias desde Documentacion/requirements.txt.
    
    Args:
        t: Diccionario de traducciones
        
    Returns:
        True si la instalación fue exitosa
    """
    print_colored(f"\n  {t['installing_deps']}", Colors.YELLOW)
    print_colored(f"  {t['this_may_take']}", Colors.YELLOW)
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    req_path = os.path.join(base_dir, "Documentacion", "requirements.txt")
    if not os.path.exists(req_path):
        print_colored(f"\n  [!] Error: {req_path} not found.", Colors.RED)
        return False

    try:
        # Intentar con pip
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '-r', req_path],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print_colored(f"\n  ✓ {t['deps_installed']}", Colors.GREEN)
            return True
        else:
            print_colored(f"\n  ✗ {t['deps_error']}", Colors.RED)
            print_colored(f"  Error details: {result.stderr}", Colors.RED)
            return False
    except Exception as e:
        print_colored(f"\n  ✗ {t['deps_error']}: {str(e)}", Colors.RED)
        return False

def verify_installation(t: Dict[str, str]) -> bool:
    """
    Verifica que la instalación sea correcta.
    
    Args:
        t: Diccionario de traducciones
        
    Returns:
        True si la verificación fue exitosa
    """
    print_colored(f"\n  {t['verifying']}", Colors.YELLOW)
    
    try:
        # Verificar imports principales
        import requests
        import bs4
        import colorama
        import yaml
        
        # Verificar estructura de directorios
        base_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        required_dirs = [
            'web_security_scanner',
            'web_security_scanner/core',
            'web_security_scanner/modules',
            'web_security_scanner/PAYLOAD',
        ]
        
        for dir_path in required_dirs:
            if not (base_dir / dir_path).exists():
                print_colored(f"  ✗ Missing directory: {dir_path}", Colors.RED)
                return False
        
        print_colored(f"  ✓ {t['verify_success']}", Colors.GREEN)
        return True
        
    except ImportError as e:
        print_colored(f"  ✗ {t['verify_error']}: {e}", Colors.RED)
        return False

def print_quick_start(language: str):
    """
    Muestra guía de inicio rápido.
    
    Args:
        language: Código del idioma
    """
    t = get_translations(language)
    
    print_colored("\n" + "="*70, Colors.GREEN)
    print_colored(f"  {t['install_complete']}", Colors.GREEN + Colors.BOLD)
    print_colored("="*70, Colors.GREEN)
    
    print_colored(f"\n  📚 {t['quick_start']}", Colors.BOLD)
    print_colored("  " + "-"*68, Colors.BLUE)
    
    print(f"\n  1️⃣  {t['test_command']}")
    print(f"      python web_security_scanner/test_architecture.py")
    
    print(f"\n  2️⃣  {t['scan_command']}")
    print(f"      python web_security_scanner/scanner_v4.py -u https://example.com --tech-only")
    
    print(f"\n  3️⃣  {t['full_scan']}")
    print(f"      python web_security_scanner/scanner_v4.py -u https://example.com -v")
    
    print_colored(f"\n  📖 {t['documentation']}", Colors.BOLD)
    print_colored("  " + "-"*68, Colors.BLUE)
    print("      README_v4.md")
    print("      GUIA_USO.md")
    print("      RESUMEN_MEJORAS.md")
    
    print_colored(f"\n  {t['enjoy']}", Colors.CYAN + Colors.BOLD)
    print()

def launch_gui():
    """Lanza la interfaz gráfica."""
    print_colored("\n  🚀 Launching GUI...", Colors.CYAN)
    launcher_path = os.path.join("web_security_scanner", "launcher_async.py")
    try:
        subprocess.Popen([sys.executable, launcher_path])
    except Exception as e:
        print_colored(f"  ✗ Error launching GUI: {e}", Colors.RED)

def main():
    """Función principal del instalador."""
    try:
        print_banner()
        
        # Check if already configured
        config_path = Path('config.yaml')
        if config_path.exists():
            print_colored("\n  [!] Configuration found. Checking dependencies...", Colors.YELLOW)
            try:
                import aiohttp
                import yaml
                print_colored("  ✓ Dependencies found.", Colors.GREEN)
                launch_gui()
                return 0
            except ImportError:
                print_colored("  [!] Dependencies missing. Proceeding with installation...", Colors.YELLOW)

        # Selección de idioma
        language = select_language()
        t = get_translations(language)
        
        # Selección de perfil
        profile = select_profile(t)
        
        # Configuraciones personalizadas
        custom_settings = get_custom_settings(t)
        
        # Crear configuración
        print_colored(f"\n  {t['creating_config']}", Colors.YELLOW)
        create_config(language, profile, custom_settings)
        print_colored(f"  ✓ {t['config_created']}", Colors.GREEN)
        
        # Instalar dependencias
        deps_ok = install_dependencies(t)
        
        # Verificar instalación
        if deps_ok:
            verify_ok = verify_installation(t)
            
            if verify_ok:
                print_quick_start(language)
                launch_gui()
                return 0
        
        return 1
        
    except KeyboardInterrupt:
        print_colored("\n\n  Installation cancelled by user.", Colors.YELLOW)
        return 1
    except Exception as e:
        print_colored(f"\n  ✗ Unexpected error: {e}", Colors.RED)
        return 1

if __name__ == '__main__':
    sys.exit(main())
