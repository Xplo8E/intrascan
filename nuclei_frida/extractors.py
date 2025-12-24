"""Extractor engine - extract data from responses"""

import re
import json
from typing import List, Dict, Optional, Any

from .models import Extractor, ExtractorType, FridaResponse


class ExtractorEngine:
    """Execute extractors against response"""
    
    def extract(self, 
                response: FridaResponse, 
                extractors: List[Extractor]) -> Dict[str, List[str]]:
        """
        Run all extractors, return name -> values mapping
        
        Args:
            response: FridaResponse to extract from
            extractors: List of extractors from template
            
        Returns:
            Dict mapping extractor name to list of extracted values
        """
        results = {}
        
        for extractor in extractors:
            values = self._execute_extractor(response, extractor)
            if values:
                name = extractor.name or extractor.type.value
                if name in results:
                    results[name].extend(values)
                else:
                    results[name] = values
                
        return results
        
    def extract_internal(self, 
                         response: FridaResponse,
                         extractors: List[Extractor]) -> Dict[str, str]:
        """
        Extract only internal extractors as single values
        Used for feeding into matchers
        """
        result = {}
        
        for extractor in extractors:
            if extractor.internal:
                values = self._execute_extractor(response, extractor)
                if values:
                    name = extractor.name or extractor.type.value
                    result[name] = values[0] if len(values) == 1 else values
                    
        return result
        
    def _execute_extractor(self, response: FridaResponse, 
                           extractor: Extractor) -> List[str]:
        """Execute single extractor"""
        corpus = self._get_extract_part(response, extractor.part)
        
        if extractor.type == ExtractorType.REGEX:
            return self._extract_regex(
                corpus, 
                extractor.regex, 
                extractor.group,
                extractor.case_insensitive
            )
        elif extractor.type == ExtractorType.KVAL:
            return self._extract_kval(response.headers, extractor.kval)
        elif extractor.type == ExtractorType.JSON:
            return self._extract_json(corpus, extractor.json)
        elif extractor.type == ExtractorType.XPATH:
            return self._extract_xpath(corpus, extractor.xpath)
        elif extractor.type == ExtractorType.DSL:
            return self._extract_dsl(response, extractor.dsl)
        return []
        
    def _get_extract_part(self, response: FridaResponse, part: str) -> str:
        """Get response part to extract from"""
        part = part.lower() if part else "body"
        
        if part in ("", "body"):
            return response.body
        elif part in ("header", "all_headers"):
            return '\n'.join(f"{k}: {v}" for k, v in response.headers.items())
        elif part == "all":
            headers = '\n'.join(f"{k}: {v}" for k, v in response.headers.items())
            return headers + '\n\n' + response.body
        else:
            return response.body
        
    def _extract_regex(self, corpus: str, patterns: List[str], 
                       group: int = 0, case_insensitive: bool = False) -> List[str]:
        """Extract using regex patterns"""
        results = []
        flags = re.MULTILINE | re.DOTALL
        if case_insensitive:
            flags |= re.IGNORECASE
            
        for pattern in patterns:
            try:
                matches = re.findall(pattern, corpus, flags)
                for match in matches:
                    if isinstance(match, tuple):
                        # Pattern has groups
                        if group < len(match):
                            results.append(match[group])
                        elif match:
                            results.append(match[0])
                    else:
                        # No groups or group 0
                        results.append(match)
            except re.error:
                pass
                
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for r in results:
            if r not in seen:
                seen.add(r)
                unique.append(r)
                
        return unique
        
    def _extract_kval(self, headers: Dict[str, str], keys: List[str]) -> List[str]:
        """Extract key-value pairs from headers"""
        results = []
        
        # Normalize header names for matching
        normalized_headers = {
            k.lower().replace('-', '_'): v 
            for k, v in headers.items()
        }
        
        for key in keys:
            # Try exact match first
            if key in headers:
                results.append(headers[key])
            else:
                # Try normalized match
                normalized_key = key.lower().replace('-', '_')
                if normalized_key in normalized_headers:
                    results.append(normalized_headers[normalized_key])
                    
        return results
        
    def _extract_json(self, corpus: str, queries: List[str]) -> List[str]:
        """Extract using jq-style queries (simplified implementation)"""
        results = []
        
        try:
            data = json.loads(corpus)
        except json.JSONDecodeError:
            return []
            
        for query in queries:
            value = self._json_path(data, query)
            if value is not None:
                if isinstance(value, (list, dict)):
                    results.append(json.dumps(value))
                else:
                    results.append(str(value))
                    
        return results
        
    def _json_path(self, data: Any, query: str) -> Optional[Any]:
        """
        Simple JSON path extraction
        
        Supports:
        - .key.subkey
        - .key[0]
        - .key[].subkey
        """
        query = query.strip()
        
        # Remove leading dot
        if query.startswith('.'):
            query = query[1:]
            
        if not query:
            return data
            
        current = data
        parts = self._split_json_path(query)
        
        for part in parts:
            if current is None:
                return None
                
            # Handle array index
            if part.endswith(']'):
                bracket_idx = part.index('[')
                key = part[:bracket_idx]
                index_str = part[bracket_idx+1:-1]
                
                if key:
                    if isinstance(current, dict):
                        current = current.get(key)
                    else:
                        return None
                        
                if current is None:
                    return None
                    
                if index_str == '':
                    # []: return all items
                    continue
                else:
                    try:
                        idx = int(index_str)
                        if isinstance(current, list) and 0 <= idx < len(current):
                            current = current[idx]
                        else:
                            return None
                    except ValueError:
                        return None
            else:
                # Regular key access
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list):
                    # Try to access from each element
                    current = [item.get(part) for item in current if isinstance(item, dict)]
                    if len(current) == 1:
                        current = current[0]
                else:
                    return None
                    
        return current
        
    def _split_json_path(self, query: str) -> List[str]:
        """Split JSON path into parts"""
        parts = []
        current = ""
        in_bracket = False
        
        for char in query:
            if char == '[':
                in_bracket = True
                current += char
            elif char == ']':
                in_bracket = False
                current += char
            elif char == '.' and not in_bracket:
                if current:
                    parts.append(current)
                current = ""
            else:
                current += char
                
        if current:
            parts.append(current)
            
        return parts
        
    def _extract_xpath(self, corpus: str, queries: List[str]) -> List[str]:
        """Extract using XPath (basic implementation)"""
        # For full XPath support, would need lxml
        # Basic implementation using regex for common patterns
        results = []
        
        for query in queries:
            # Simple tag content extraction: //tag
            tag_match = re.match(r'//(\w+)(?:\[@\w+(?:=["\'].*?["\']\)])?$', query)
            if tag_match:
                tag = tag_match.group(1)
                pattern = f'<{tag}[^>]*>([^<]+)</{tag}>'
                matches = re.findall(pattern, corpus, re.IGNORECASE)
                results.extend(matches)
                
        return results
        
    def _extract_dsl(self, response: FridaResponse, expressions: List[str]) -> List[str]:
        """Extract using DSL expressions"""
        results = []
        
        data = {
            'status_code': response.status_code,
            'body': response.body,
            'content_length': len(response.body),
        }
        data.update(response.headers)
        
        for expr in expressions:
            # Simple variable reference
            if expr in data:
                results.append(str(data[expr]))
            # len(body) style
            elif expr.startswith('len(') and expr.endswith(')'):
                var_name = expr[4:-1]
                if var_name in data:
                    results.append(str(len(str(data[var_name]))))
                    
        return results
