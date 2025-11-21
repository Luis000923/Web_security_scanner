import yaml
import os
from typing import Dict, Any

class I18n:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(I18n, cls).__new__(cls)
            cls._instance.translations = {}
            cls._instance.current_lang = 'en'
        return cls._instance

    def load_languages(self, filepath: str):
        """Load translations from a YAML file."""
        if not os.path.exists(filepath):
            return
            
        with open(filepath, 'r', encoding='utf-8') as f:
            self.translations = yaml.safe_load(f)

    def set_language(self, lang: str):
        """Set the current language."""
        if lang in self.translations:
            self.current_lang = lang

    def get(self, key: str, **kwargs) -> str:
        """
        Get a translation for the given key (dot notation).
        Example: i18n.get('gui.start_scan')
        """
        keys = key.split('.')
        value = self.translations.get(self.current_lang, {})
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return key
        
        if value is None:
            return key
            
        if isinstance(value, str):
            return value.format(**kwargs)
            
        return str(value)

# Global instance
i18n = I18n()
