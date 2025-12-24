"""Matcher engine - validate responses against template matchers"""

import re
from typing import Tuple, List, Dict, Any, Optional

from .models import Matcher, MatcherType, FridaResponse


class MatcherEngine:
    """Execute matchers against response (matching Nuclei behavior)"""
    
    def match(self, 
              response: FridaResponse, 
              matchers: List[Matcher],
              matchers_condition: str = "or",
              extracted_vars: Optional[Dict[str, Any]] = None) -> Tuple[bool, List[str]]:
        """
        Execute all matchers against response
        
        Args:
            response: FridaResponse to match against
            matchers: List of matchers from template
            matchers_condition: "and" or "or" between matchers
            extracted_vars: Variables from extractors (for DSL)
            
        Returns:
            Tuple of (matched: bool, matched_snippets: List[str])
        """
        if not matchers:
            return False, []
            
        results = []
        all_snippets = []
        
        for matcher in matchers:
            matched, snippets = self._execute_matcher(response, matcher, extracted_vars)
            results.append(matched)
            all_snippets.extend(snippets)
            
            # Short-circuit OR: first match wins
            if matchers_condition.lower() == "or" and matched:
                return True, snippets
                
            # Short-circuit AND: first failure loses
            if matchers_condition.lower() == "and" and not matched:
                return False, []
        
        # AND: all must pass
        if matchers_condition.lower() == "and":
            return all(results), all_snippets
            
        # OR: any must pass
        return any(results), all_snippets
        
    def _execute_matcher(self, 
                         response: FridaResponse, 
                         matcher: Matcher,
                         extracted_vars: Optional[Dict] = None) -> Tuple[bool, List[str]]:
        """Execute single matcher"""
        
        # Get the part to match against
        corpus = self._get_match_part(response, matcher.part)
        
        # Execute by type
        if matcher.type == MatcherType.STATUS:
            result = self._match_status(response.status_code, matcher.status)
            snippets = [str(response.status_code)] if result else []
            
        elif matcher.type == MatcherType.WORD:
            result, snippets = self._match_words(
                corpus, 
                matcher.words, 
                matcher.condition,
                matcher.case_insensitive
            )
            
        elif matcher.type == MatcherType.REGEX:
            result, snippets = self._match_regex(corpus, matcher.regex)
            
        elif matcher.type == MatcherType.DSL:
            result = self._match_dsl(response, matcher.dsl, extracted_vars)
            snippets = []
            
        elif matcher.type == MatcherType.BINARY:
            result, snippets = self._match_binary(corpus, matcher.binary)
            
        elif matcher.type == MatcherType.SIZE:
            result = self._match_size(len(corpus), matcher.size)
            snippets = [str(len(corpus))] if result else []
        else:
            result, snippets = False, []
            
        # Handle negative
        if matcher.negative:
            result = not result
            snippets = [] if result else snippets  # Clear snippets if negated match
            
        return result, snippets
        
    def _get_match_part(self, response: FridaResponse, part: str) -> str:
        """Get response part to match against"""
        part = part.lower() if part else "body"
        
        if part in ("", "body"):
            return response.body
        elif part in ("header", "all_headers"):
            return '\n'.join(f"{k}: {v}" for k, v in response.headers.items())
        elif part == "all":
            headers = '\n'.join(f"{k}: {v}" for k, v in response.headers.items())
            return headers + '\n\n' + response.body
        elif part == "status_code":
            return str(response.status_code)
        else:
            # Could be a specific header name
            return response.headers.get(part, response.headers.get(part.title(), ''))
            
    def _match_status(self, status_code: int, expected: List[int]) -> bool:
        """Match HTTP status code"""
        return status_code in expected
        
    def _match_size(self, size: int, expected: List[int]) -> bool:
        """Match content size"""
        return size in expected
        
    def _match_words(self, corpus: str, words: List[str], 
                     condition: str, case_insensitive: bool) -> Tuple[bool, List[str]]:
        """Match words in corpus"""
        if case_insensitive:
            corpus = corpus.lower()
            words = [w.lower() for w in words]
            
        matched = []
        for word in words:
            if word in corpus:
                matched.append(word)
                # OR: first match is enough
                if condition.lower() == "or":
                    return True, [word]
            else:
                # AND: any miss is failure
                if condition.lower() == "and":
                    return False, []
                
        # AND: all must match
        if condition.lower() == "and":
            return len(matched) == len(words), matched
            
        # OR: any match is success
        return len(matched) > 0, matched
        
    def _match_regex(self, corpus: str, patterns: List[str]) -> Tuple[bool, List[str]]:
        """Match regex patterns in corpus"""
        matched = []
        for pattern in patterns:
            try:
                matches = re.findall(pattern, corpus, re.MULTILINE | re.DOTALL)
                if matches:
                    # Flatten tuples from groups
                    for match in matches:
                        if isinstance(match, tuple):
                            matched.extend([m for m in match if m])
                        else:
                            matched.append(match)
            except re.error:
                pass
        return len(matched) > 0, matched
        
    def _match_binary(self, corpus: str, hex_patterns: List[str]) -> Tuple[bool, List[str]]:
        """Match binary hex patterns"""
        matched = []
        try:
            corpus_bytes = corpus.encode('latin-1')
        except:
            return False, []
            
        for hex_pattern in hex_patterns:
            try:
                pattern_bytes = bytes.fromhex(hex_pattern)
                if pattern_bytes in corpus_bytes:
                    matched.append(hex_pattern)
            except ValueError:
                pass
                
        return len(matched) > 0, matched
        
    def _match_dsl(self, response: FridaResponse, expressions: List[str], 
                   extracted_vars: Optional[Dict] = None) -> bool:
        """
        Evaluate DSL expressions
        
        Supported functions:
        - contains(str, substr)
        - contains_any(str, substr1, substr2, ...)
        - status_code == N
        - len(body) > N
        """
        # Build data dict
        data = {
            'status_code': response.status_code,
            'body': response.body,
            'header': '\n'.join(f"{k}: {v}" for k, v in response.headers.items()),
            'all_headers': '\n'.join(f"{k}: {v}" for k, v in response.headers.items()),
            'content_length': len(response.body),
            'duration': response.duration,
        }
        
        # Add headers with normalized names
        for k, v in response.headers.items():
            data[k.lower().replace('-', '_')] = v
            
        if extracted_vars:
            data.update(extracted_vars)
            
        for expr in expressions:
            if not self._eval_dsl_expr(expr, data):
                return False
        return True
        
    def _eval_dsl_expr(self, expr: str, data: Dict) -> bool:
        """Evaluate a single DSL expression"""
        expr = expr.strip()
        
        # Handle contains(body, "text")
        contains_match = re.match(r'contains\s*\(\s*(\w+)\s*,\s*["\']([^"\']+)["\']\s*\)', expr)
        if contains_match:
            var_name, search_text = contains_match.groups()
            var_value = str(data.get(var_name, ''))
            return search_text in var_value
            
        # Handle contains_any(body, "a", "b", ...)
        contains_any_match = re.match(r'contains_any\s*\(\s*(\w+)\s*,\s*(.+)\)', expr)
        if contains_any_match:
            var_name = contains_any_match.group(1)
            rest = contains_any_match.group(2)
            var_value = str(data.get(var_name, ''))
            
            # Extract quoted strings
            search_texts = re.findall(r'["\']([^"\']+)["\']', rest)
            return any(text in var_value for text in search_texts)
            
        # Handle status_code == N
        status_match = re.match(r'status_code\s*(==|!=|>|<|>=|<=)\s*(\d+)', expr)
        if status_match:
            op, value = status_match.groups()
            status = data.get('status_code', 0)
            value = int(value)
            return self._compare(status, op, value)
            
        # Handle len(body) > N
        len_match = re.match(r'len\s*\(\s*(\w+)\s*\)\s*(==|!=|>|<|>=|<=)\s*(\d+)', expr)
        if len_match:
            var_name, op, value = len_match.groups()
            var_value = str(data.get(var_name, ''))
            return self._compare(len(var_value), op, int(value))
            
        # Handle simple boolean expressions with &&
        if '&&' in expr:
            parts = expr.split('&&')
            return all(self._eval_dsl_expr(p.strip(), data) for p in parts)
            
        # Handle simple boolean expressions with ||
        if '||' in expr:
            parts = expr.split('||')
            return any(self._eval_dsl_expr(p.strip(), data) for p in parts)
        
        # Default: unknown expression
        return False
        
    def _compare(self, left: int, op: str, right: int) -> bool:
        """Compare two values"""
        if op == '==':
            return left == right
        elif op == '!=':
            return left != right
        elif op == '>':
            return left > right
        elif op == '<':
            return left < right
        elif op == '>=':
            return left >= right
        elif op == '<=':
            return left <= right
        return False
