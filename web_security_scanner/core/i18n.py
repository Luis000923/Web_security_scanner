#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema de Internacionalización (i18n)
======================================

Este módulo proporciona soporte multiidioma para el Web Security Scanner.
Permite cambiar el idioma de la interfaz entre inglés y español.

Conexiones:
-----------
- Usado por: scanner_v4.py, todos los testers, logger.py
- Depende de: Ningún módulo interno (standalone)
- Lee: languages.yaml (archivo de traducciones)
"""

import yaml
import os
from pathlib import Path
from typing import Dict, Any

class I18n:
    """
    Gestor de internacionalización.
    
    Carga y gestiona las traducciones en múltiples idiomas.
    Proporciona acceso a strings traducidos mediante claves.
    """
    
    SUPPORTED_LANGUAGES = ['es', 'en']
    DEFAULT_LANGUAGE = 'en'
    
    def __init__(self, language: str = None):
        """
        Inicializa el gestor de idiomas.
        
        Args:
            language: Código del idioma ('es' o 'en'). Si es None, lee config.
        """
        self.current_language = language or self._load_user_preference() or self.DEFAULT_LANGUAGE
        self.translations: Dict[str, Dict[str, Any]] = {}
        self._load_translations()
    
    def _load_user_preference(self) -> str:
        """
        Carga la preferencia de idioma del usuario desde config.yaml.
        
        Returns:
            Código del idioma configurado o None
        """
        try:
            config_path = Path(__file__).parent.parent.parent / 'config.yaml'
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    return config.get('language', self.DEFAULT_LANGUAGE)
        except Exception:
            pass
        return None
    
    def _load_translations(self):
        """
        Carga las traducciones desde el archivo languages.yaml.
        """
        try:
            lang_file = Path(__file__).parent.parent.parent / 'languages.yaml'
            if lang_file.exists():
                with open(lang_file, 'r', encoding='utf-8') as f:
                    self.translations = yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load translations: {e}")
            self.translations = self._get_default_translations()
    
    def _get_default_translations(self) -> Dict[str, Dict[str, Any]]:
        """
        Traducciones por defecto si no se puede cargar el archivo.
        
        Returns:
            Diccionario con traducciones básicas
        """
        return {
            'en': {
                'scanner': {
                    'starting': 'Starting security scan...',
                    'completed': 'Scan completed!',
                    'error': 'Error during scan'
                }
            },
            'es': {
                'scanner': {
                    'starting': 'Iniciando escaneo de seguridad...',
                    'completed': '¡Escaneo completado!',
                    'error': 'Error durante el escaneo'
                }
            }
        }
    
    def get(self, key_path: str, **kwargs) -> str:
        """
        Obtiene una traducción por su ruta de clave.
        
        Args:
            key_path: Ruta de la clave separada por puntos (ej: 'scanner.starting')
            **kwargs: Variables para formatear el string
        
        Returns:
            String traducido al idioma actual
        
        Ejemplo:
            >>> i18n = I18n('es')
            >>> i18n.get('scanner.starting')
            'Iniciando escaneo de seguridad...'
            >>> i18n.get('vulnerabilities.found', count=5)
            'Se encontraron 5 vulnerabilidades'
        """
        keys = key_path.split('.')
        value = self.translations.get(self.current_language, {})
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                break
        
        # Si no se encuentra, intentar en inglés como fallback
        if value is None and self.current_language != 'en':
            value = self.translations.get('en', {})
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key)
                else:
                    break
        
        # Si aún no se encuentra, retornar la clave
        if value is None:
            return key_path
        
        # Formatear con kwargs si es necesario
        if kwargs and isinstance(value, str):
            try:
                return value.format(**kwargs)
            except KeyError:
                return value
        
        return str(value)
    
    def set_language(self, language: str):
        """
        Cambia el idioma actual.
        
        Args:
            language: Código del idioma ('es' o 'en')
        """
        if language in self.SUPPORTED_LANGUAGES:
            self.current_language = language
        else:
            raise ValueError(f"Unsupported language: {language}")
    
    def get_language(self) -> str:
        """
        Obtiene el idioma actual.
        
        Returns:
            Código del idioma actual
        """
        return self.current_language


# Instancia global para fácil acceso
_i18n_instance = None

def get_i18n(language: str = None) -> I18n:
    """
    Obtiene la instancia global de I18n.
    
    Args:
        language: Código del idioma (opcional)
    
    Returns:
        Instancia de I18n
    """
    global _i18n_instance
    if _i18n_instance is None or language is not None:
        _i18n_instance = I18n(language)
    return _i18n_instance


def t(key: str, **kwargs) -> str:
    """
    Función abreviada para traducción.
    
    Args:
        key: Ruta de la clave de traducción
        **kwargs: Variables para formatear
    
    Returns:
        String traducido
    
    Ejemplo:
        >>> t('scanner.starting')
        'Starting security scan...'
    """
    return get_i18n().get(key, **kwargs)
