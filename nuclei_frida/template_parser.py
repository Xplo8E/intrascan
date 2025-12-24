"""Template parser - parse Nuclei YAML templates"""

from pathlib import Path
from typing import Optional, List
import yaml

from .models import (
    NucleiTemplate,
    TemplateInfo,
    HttpRequest,
    Matcher,
    Extractor,
)


class TemplateParser:
    """Parse Nuclei YAML templates to data models"""
    
    def parse_file(self, yaml_path: str) -> Optional[NucleiTemplate]:
        """
        Parse a template file
        
        Returns None if file is invalid or not an HTTP template
        """
        try:
            with open(yaml_path, 'r') as f:
                content = f.read()
            return self.parse_content(content, yaml_path)
        except Exception as e:
            # Log error but don't crash - skip invalid templates
            return None
    
    def parse_content(self, content: str, source_path: str = "") -> Optional[NucleiTemplate]:
        """Parse template from string content"""
        try:
            data = yaml.safe_load(content)
            
            if not data or not isinstance(data, dict):
                return None
                
            # Must have id and info
            template_id = data.get("id")
            info_data = data.get("info")
            
            if not template_id or not info_data:
                return None
                
            # Must have http section (we only support HTTP)
            http_data = data.get("http")
            if not http_data:
                # Also check for deprecated 'requests' key
                http_data = data.get("requests")
            
            if not http_data or not isinstance(http_data, list):
                return None
                
            # Parse components
            info = TemplateInfo.from_dict(info_data)
            http_requests = [HttpRequest.from_dict(r) for r in http_data]
            
            # Parse variables if present
            variables = data.get("variables", {})
            
            return NucleiTemplate(
                id=template_id,
                info=info,
                http_requests=http_requests,
                variables=variables,
                path=source_path,
            )
            
        except yaml.YAMLError:
            return None
        except Exception:
            return None
    
    def parse_multiple(self, paths: List[str]) -> List[NucleiTemplate]:
        """Parse multiple templates, skipping invalid ones"""
        templates = []
        
        for path in paths:
            template = self.parse_file(path)
            if template:
                templates.append(template)
                
        return templates
