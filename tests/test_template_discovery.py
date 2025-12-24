"""Tests for template discovery"""

import pytest
import tempfile
import os
from pathlib import Path

from intrascan.template_discovery import TemplateDiscovery


class TestTemplateDiscovery:
    """Test template discovery functionality"""
    
    def setup_method(self):
        """Create temporary directory with test templates"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test templates
        self.templates = []
        
        # Critical severity template
        self._create_template("cve-2024-001.yaml", "critical", ["cve", "rce"])
        
        # High severity template
        self._create_template("cve-2024-002.yaml", "high", ["cve", "sqli"])
        
        # Medium severity template
        self._create_template("panel-detect.yaml", "medium", ["panel", "detect"])
        
        # Low severity template
        self._create_template("info-disclosure.yaml", "low", ["info"])
        
        # Info severity template in subdirectory
        subdir = os.path.join(self.temp_dir, "subdir")
        os.makedirs(subdir)
        self._create_template("version-detect.yaml", "info", ["detect"], subdir)
        
    def teardown_method(self):
        """Clean up temporary directory"""
        import shutil
        shutil.rmtree(self.temp_dir)
        
    def _create_template(self, name, severity, tags, directory=None):
        """Helper to create test template"""
        dir_path = directory or self.temp_dir
        path = os.path.join(dir_path, name)
        
        content = f"""
id: {name.replace('.yaml', '')}
info:
  name: Test Template
  severity: {severity}
  tags: {','.join(tags)}
http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}"
    matchers:
      - type: status
        status: [200]
"""
        with open(path, 'w') as f:
            f.write(content)
        self.templates.append(path)
        
    def test_discover_from_directory(self):
        """Test discovering all templates in directory"""
        discovery = TemplateDiscovery(self.temp_dir)
        templates = discovery.discover()
        
        assert len(templates) == 5  # All templates including subdirectory
        
    def test_discover_from_single_file(self):
        """Test discovering single file"""
        single_file = self.templates[0]
        discovery = TemplateDiscovery(single_file)
        templates = discovery.discover()
        
        assert len(templates) == 1
        # Compare basenames to avoid macOS /private/var symlink issues
        assert os.path.basename(templates[0]) == os.path.basename(single_file)
        
    def test_discover_recursive(self):
        """Test recursive discovery finds subdirectory templates"""
        discovery = TemplateDiscovery(self.temp_dir)
        templates = discovery.discover()
        
        # Should include template in subdir
        subdir_templates = [t for t in templates if "subdir" in t]
        assert len(subdir_templates) == 1
        
    def test_filter_by_severity_single(self):
        """Test filtering by single severity"""
        discovery = TemplateDiscovery(self.temp_dir)
        all_templates = discovery.discover()
        
        critical = discovery.filter_by_severity(all_templates, ["critical"])
        
        assert len(critical) == 1
        assert "cve-2024-001" in critical[0]
        
    def test_filter_by_severity_multiple(self):
        """Test filtering by multiple severities"""
        discovery = TemplateDiscovery(self.temp_dir)
        all_templates = discovery.discover()
        
        high_and_critical = discovery.filter_by_severity(
            all_templates, ["critical", "high"]
        )
        
        assert len(high_and_critical) == 2
        
    def test_filter_by_tags_include(self):
        """Test filtering by included tags"""
        discovery = TemplateDiscovery(self.temp_dir)
        all_templates = discovery.discover()
        
        cve_templates = discovery.filter_by_tags(
            all_templates, include_tags=["cve"]
        )
        
        assert len(cve_templates) == 2
        
    def test_filter_by_tags_exclude(self):
        """Test filtering by excluded tags"""
        discovery = TemplateDiscovery(self.temp_dir)
        all_templates = discovery.discover()
        
        non_cve = discovery.filter_by_tags(
            all_templates, exclude_tags=["cve"]
        )
        
        assert len(non_cve) == 3  # Excludes 2 CVE templates
        
    def test_filter_by_tags_include_and_exclude(self):
        """Test filtering with both include and exclude"""
        discovery = TemplateDiscovery(self.temp_dir)
        all_templates = discovery.discover()
        
        # Include CVE but exclude RCE
        filtered = discovery.filter_by_tags(
            all_templates,
            include_tags=["cve"],
            exclude_tags=["rce"]
        )
        
        assert len(filtered) == 1
        assert "cve-2024-002" in filtered[0]  # Has cve but not rce
        
    def test_discover_nonexistent_path(self):
        """Test discovering from nonexistent path raises error"""
        discovery = TemplateDiscovery("/nonexistent/path")
        
        with pytest.raises(FileNotFoundError):
            discovery.discover()
            
    def test_filter_empty_list(self):
        """Test filtering empty list returns empty"""
        discovery = TemplateDiscovery(self.temp_dir)
        
        filtered = discovery.filter_by_severity([], ["critical"])
        assert filtered == []
        
    def test_filter_no_filters(self):
        """Test filtering with no filters returns original list"""
        discovery = TemplateDiscovery(self.temp_dir)
        all_templates = discovery.discover()
        
        # No severities filter
        filtered1 = discovery.filter_by_severity(all_templates, None)
        assert filtered1 == all_templates
        
        # No tags filter
        filtered2 = discovery.filter_by_tags(all_templates, None, None)
        assert filtered2 == all_templates
