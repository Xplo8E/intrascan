"""Template discovery - find templates in directory trees"""

import os
from pathlib import Path
from typing import List, Optional, Set
import yaml


class TemplateDiscovery:
    """Discover Nuclei templates from directory or file path"""
    
    TEMPLATE_EXTENSIONS = {".yaml", ".yml"}
    
    def __init__(self, base_path: str):
        self.base_path = Path(base_path).resolve()
        
    def discover(self) -> List[str]:
        """
        Find all template files
        
        Handles:
        - Single file: /path/to/template.yaml
        - Directory: /path/to/templates/ (recursive)
        """
        templates = []
        
        if self.base_path.is_file():
            if self._is_template_file(self.base_path):
                templates.append(str(self.base_path))
        elif self.base_path.is_dir():
            templates = self._scan_directory(self.base_path)
        else:
            raise FileNotFoundError(f"Path not found: {self.base_path}")
            
        return sorted(templates)
    
    def _scan_directory(self, directory: Path) -> List[str]:
        """Recursively scan directory for template files"""
        templates = []
        
        # Check for .nuclei-ignore file
        ignore_patterns = self._load_ignore_patterns(directory)
        
        for root, dirs, files in os.walk(directory):
            root_path = Path(root)
            
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                file_path = root_path / file
                
                if self._is_template_file(file_path):
                    # Check ignore patterns
                    if not self._is_ignored(file_path, ignore_patterns):
                        templates.append(str(file_path))
                        
        return templates
    
    def _is_template_file(self, path: Path) -> bool:
        """Check if file is a Nuclei template"""
        return path.suffix.lower() in self.TEMPLATE_EXTENSIONS
    
    def _load_ignore_patterns(self, directory: Path) -> Set[str]:
        """Load patterns from .nuclei-ignore file"""
        ignore_file = directory / ".nuclei-ignore"
        patterns = set()
        
        if ignore_file.exists():
            with open(ignore_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns.add(line)
                        
        return patterns
    
    def _is_ignored(self, path: Path, patterns: Set[str]) -> bool:
        """Check if path matches any ignore pattern"""
        path_str = str(path)
        for pattern in patterns:
            if pattern in path_str:
                return True
        return False
        
    def filter_by_severity(self, templates: List[str], 
                          severities: List[str]) -> List[str]:
        """Filter templates by severity level"""
        if not severities:
            return templates
            
        severities_lower = {s.lower() for s in severities}
        filtered = []
        
        for template_path in templates:
            severity = self._get_template_severity(template_path)
            if severity and severity.lower() in severities_lower:
                filtered.append(template_path)
                
        return filtered
    
    def filter_by_tags(self, templates: List[str],
                      include_tags: Optional[List[str]] = None,
                      exclude_tags: Optional[List[str]] = None) -> List[str]:
        """Filter templates by tags"""
        if not include_tags and not exclude_tags:
            return templates
            
        include_set = {t.lower() for t in (include_tags or [])}
        exclude_set = {t.lower() for t in (exclude_tags or [])}
        filtered = []
        
        for template_path in templates:
            tags = self._get_template_tags(template_path)
            tags_lower = {t.lower() for t in tags}
            
            # Check exclusion first
            if exclude_set and tags_lower & exclude_set:
                continue
                
            # Check inclusion
            if include_set:
                if tags_lower & include_set:
                    filtered.append(template_path)
            else:
                filtered.append(template_path)
                
        return filtered
    
    def _get_template_severity(self, path: str) -> Optional[str]:
        """Quick parse to get severity from template"""
        try:
            with open(path) as f:
                # Read first ~50 lines to find severity
                content = ""
                for i, line in enumerate(f):
                    if i > 50:
                        break
                    content += line
                    if "severity:" in line:
                        # Quick extraction
                        return line.split("severity:")[-1].strip()
        except Exception:
            pass
        return None
    
    def _get_template_tags(self, path: str) -> List[str]:
        """Quick parse to get tags from template"""
        try:
            with open(path) as f:
                for i, line in enumerate(f):
                    if i > 50:
                        break
                    if "tags:" in line:
                        tags_str = line.split("tags:")[-1].strip()
                        return [t.strip() for t in tags_str.split(",")]
        except Exception:
            pass
        return []
