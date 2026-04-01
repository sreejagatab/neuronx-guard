"""NeuronX Guard Unit Tests."""
import sys
import os
import json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


# --- Config Parsing ---

class TestConfig:
    def test_default_config(self):
        from guard_server import get_repo_config
        config = get_repo_config("nonexistent/repo", "fake-token")
        assert config["enabled"] is True
        assert config["checks"]["security"] is True
        assert config["checks"]["llm_review"] is True
        assert "*.md" in config["ignore_files"]

    def test_config_has_all_checks(self):
        from guard_server import get_repo_config
        config = get_repo_config("test/repo", "")
        checks = config["checks"]
        assert "security" in checks
        assert "complexity" in checks
        assert "bare_except" in checks
        assert "patterns" in checks
        assert "llm_review" in checks


# --- Diff Parsing ---

class TestDiffParsing:
    def test_parse_single_file(self):
        from guard_server import parse_diff
        diff = "diff --git a/test.py b/test.py\n+line1\n+line2\n"
        files = parse_diff(diff)
        assert len(files) == 1
        assert files[0][0] == "test.py"

    def test_parse_multiple_files(self):
        from guard_server import parse_diff
        diff = "diff --git a/a.py b/a.py\n+code1\ndiff --git a/b.py b/b.py\n+code2\n"
        files = parse_diff(diff)
        assert len(files) == 2
        assert files[0][0] == "a.py"
        assert files[1][0] == "b.py"

    def test_parse_empty_diff(self):
        from guard_server import parse_diff
        files = parse_diff("")
        assert len(files) == 0


# --- Review Engine ---

class TestReviewEngine:
    def get_config(self, **overrides):
        config = {
            "enabled": True,
            "checks": {"security": True, "complexity": True, "bare_except": True, "patterns": False, "llm_review": False},
            "ignore_files": [],
        }
        config.update(overrides)
        return config

    def test_bare_except_detection(self):
        from guard_server import review_file
        diff = "+def foo():\n+    try:\n+        pass\n+    except:\n+        pass\n"
        issues = review_file("test.py", diff, self.get_config())
        bare = [i for i in issues if i["check"] == "bare_except"]
        assert len(bare) >= 1

    def test_hardcoded_password_detection(self):
        from guard_server import review_file
        diff = '+password = "super_secret_123"\n'
        issues = review_file("test.py", diff, self.get_config())
        security = [i for i in issues if i["check"] == "security"]
        assert len(security) >= 1
        assert security[0]["severity"] == "error"

    def test_hardcoded_api_key_detection(self):
        from guard_server import review_file
        diff = '+api_key = "sk-proj-abcdef123456789"\n'
        issues = review_file("test.py", diff, self.get_config())
        security = [i for i in issues if i["check"] == "security"]
        assert len(security) >= 1

    def test_github_token_detection(self):
        from guard_server import review_file
        diff = '+token = "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789"\n'
        issues = review_file("test.py", diff, self.get_config())
        security = [i for i in issues if i["check"] == "security"]
        assert len(security) >= 1

    def test_clean_code_no_issues(self):
        from guard_server import review_file
        diff = '+def add(a, b):\n+    return a + b\n'
        issues = review_file("test.py", diff, self.get_config())
        # Should have no bare_except or security issues
        critical = [i for i in issues if i["check"] in ("bare_except", "security")]
        assert len(critical) == 0

    def test_ignored_files_skipped(self):
        from guard_server import review_file
        config = self.get_config()
        config["ignore_files"] = ["*.md"]
        issues = review_file("README.md", "+password = 'secret'\n", config)
        assert len(issues) == 0

    def test_complexity_detection(self):
        from guard_server import review_file
        # Build a complex function
        code = "+def complex():\n"
        for i in range(20):
            code += "+    if x%d > 0:\n" % i
            code += "+        pass\n"
        issues = review_file("test.py", code, self.get_config())
        complexity = [i for i in issues if i["check"] == "complexity"]
        assert len(complexity) >= 1


# --- Review Comment Formatting ---

class TestFormatting:
    def test_no_issues_message(self):
        from guard_server import format_review_comment
        comment = format_review_comment("test/repo", 3, [])
        assert "No issues found" in comment
        assert "NeuronX" in comment

    def test_issues_formatted(self):
        from guard_server import format_review_comment
        issues = [
            ("file.py", {"severity": "error", "message": "Bad code", "check": "security"}),
            ("file.py", {"severity": "warning", "message": "Meh code", "check": "llm"}),
        ]
        comment = format_review_comment("test/repo", 1, issues)
        assert "2" in comment  # 2 issues
        assert "file.py" in comment
        assert "NeuronX Guard" in comment


# --- Rate Limiting ---

class TestRateLimiting:
    def test_free_tier_limit(self):
        from guard_db import check_rate_limit
        result = check_rate_limit(999999)  # Non-existent installation
        assert result["tier"] == "free"
        assert result["limit"] == 20
        assert result["allowed"] is True

    def test_pricing_tiers_exist(self):
        from guard_db import TIERS
        assert "free" in TIERS
        assert "pro" in TIERS
        assert "team" in TIERS
        assert TIERS["free"]["price"] == 0
        assert TIERS["pro"]["price"] == 10
        assert TIERS["team"]["price"] == 30


# --- Sanitization ---

class TestSanitization:
    def test_token_filter(self):
        from guard_server import _SanitizeFilter
        f = _SanitizeFilter()
        import logging
        record = logging.LogRecord("test", logging.INFO, "", 0, "Token ghp_ABCDEFghijklmnopqrstuvwxyz0123456789 found", (), None)
        f.filter(record)
        assert "ghp_***" in record.msg
        assert "ghp_ABCDEF" not in record.msg


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
