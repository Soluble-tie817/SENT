from __future__ import annotations

"""
PHP suspicious pattern detection for WordPress plugins.

Since we can't use Python's ast module for PHP, we use targeted regex
patterns specific to PHP/WordPress attack vectors.

These are NOT generic regex — they're tuned for WordPress plugin attacks:
  - eval/exec of encoded payloads
  - backdoor installation
  - credential theft from wp-config.php
  - unauthorized admin creation
  - file upload bypasses
  - database injection
"""

import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass(frozen=True)
class PHPPattern:
    category: str
    name: str
    regex: re.Pattern
    score: int
    description: str


PHP_PATTERNS: List[PHPPattern] = [
    # ---- Code execution (critical in WordPress context) ----
    PHPPattern("execution", "eval_call",
               re.compile(r'\beval\s*\('), 20,
               "eval() — arbitrary PHP execution"),
    PHPPattern("execution", "assert_call",
               re.compile(r'\bassert\s*\('), 15,
               "assert() — can execute code in PHP"),
    PHPPattern("execution", "preg_replace_e",
               re.compile(r'preg_replace\s*\(\s*["\'].*?/e["\']'), 25,
               "preg_replace with /e modifier — code execution"),
    PHPPattern("execution", "create_function",
               re.compile(r'\bcreate_function\s*\('), 20,
               "create_function() — dynamic code creation"),
    PHPPattern("execution", "call_user_func",
               re.compile(r'call_user_func(_array)?\s*\('), 10,
               "call_user_func — dynamic function call"),
    PHPPattern("execution", "system_exec",
               re.compile(r'\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\('), 25,
               "System command execution"),
    PHPPattern("execution", "backtick_exec",
               re.compile(r'`[^`]+`'), 15,
               "Backtick operator — shell execution"),

    # ---- Obfuscation (very common in WP malware) ----
    PHPPattern("obfuscation", "base64_decode",
               re.compile(r'base64_decode\s*\('), 15,
               "base64_decode — common obfuscation"),
    PHPPattern("obfuscation", "gzinflate",
               re.compile(r'(gzinflate|gzuncompress|gzdecode)\s*\('), 15,
               "Compression decompression — layered obfuscation"),
    PHPPattern("obfuscation", "str_rot13",
               re.compile(r'str_rot13\s*\('), 10,
               "str_rot13 — simple obfuscation"),
    PHPPattern("obfuscation", "chr_concat",
               re.compile(r'chr\s*\(\s*\d+\s*\)\s*\.'), 15,
               "Character-by-character string construction"),
    PHPPattern("obfuscation", "hex_escape",
               re.compile(r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}'), 10,
               "Hex-escaped strings"),
    PHPPattern("obfuscation", "long_encoded_string",
               re.compile(r'["\'][A-Za-z0-9+/=]{200,}["\']'), 20,
               "Long encoded string literal"),
    PHPPattern("obfuscation", "variable_variable",
               re.compile(r'\$\$\w+|\$\{["\']'), 10,
               "Variable variables — dynamic name resolution"),

    # ---- Network / remote access ----
    PHPPattern("network", "curl_exec",
               re.compile(r'curl_exec\s*\(|curl_init\s*\('), 10,
               "cURL call — network access"),
    PHPPattern("network", "file_get_contents_url",
               re.compile(r'file_get_contents\s*\(\s*["\']https?://'), 10,
               "Remote URL fetch"),
    PHPPattern("network", "wp_remote",
               re.compile(r'wp_remote_(get|post|request|head)\s*\('), 5,
               "WordPress HTTP API call"),
    PHPPattern("network", "fsockopen",
               re.compile(r'(fsockopen|pfsockopen)\s*\('), 15,
               "Raw socket connection"),
    PHPPattern("network", "external_url",
               re.compile(r'https?://(?!localhost|127\.0\.0\.1|wordpress\.org|w\.org|wp\.org|example\.com)[^\s\'">,]{20,}'), 5,
               "External URL reference"),

    # ---- WordPress-specific attacks ----
    PHPPattern("wordpress", "wp_create_user",
               re.compile(r'wp_create_user\s*\(|wp_insert_user\s*\('), 20,
               "User creation — possible backdoor admin account"),
    PHPPattern("wordpress", "update_option_admin",
               re.compile(r'update_option\s*\(\s*["\']siteurl|update_option\s*\(\s*["\']home'), 20,
               "Modifying site URL — possible redirect attack"),
    PHPPattern("wordpress", "wp_config_read",
               re.compile(r'wp-config\.php|DB_PASSWORD|DB_USER|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY'), 25,
               "Accessing wp-config credentials"),
    PHPPattern("wordpress", "add_role_admin",
               re.compile(r"(add_role|add_cap)\s*\(.*administrator", re.IGNORECASE), 20,
               "Adding admin role/capability"),
    PHPPattern("wordpress", "wp_set_auth_cookie",
               re.compile(r'wp_set_auth_cookie\s*\(|wp_set_current_user\s*\('), 25,
               "Authentication bypass — setting auth cookie directly"),
    PHPPattern("wordpress", "nonce_bypass",
               re.compile(r'wp_verify_nonce.*(?:true|1)|check_admin_referer.*(?:true|1)'), 20,
               "Nonce verification bypass"),

    # ---- File system attacks ----
    PHPPattern("filesystem", "file_write",
               re.compile(r'(file_put_contents|fwrite|fputs)\s*\('), 10,
               "File write operation"),
    PHPPattern("filesystem", "file_upload",
               re.compile(r'\$_FILES\s*\[|move_uploaded_file\s*\('), 10,
               "File upload handling"),
    PHPPattern("filesystem", "include_remote",
               re.compile(r'(include|require|include_once|require_once)\s*\(\s*\$'), 15,
               "Dynamic include — possible remote file inclusion"),
    PHPPattern("filesystem", "chmod_write",
               re.compile(r'chmod\s*\(.*0?7[0-7]{2}'), 15,
               "Setting world-writable permissions"),
    PHPPattern("filesystem", "unlink_delete",
               re.compile(r'unlink\s*\(|rmdir\s*\('), 5,
               "File/directory deletion"),

    # ---- Sensitive data access ----
    PHPPattern("sensitive", "superglobals",
               re.compile(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\['), 3,
               "Superglobal access (context-dependent)"),
    PHPPattern("sensitive", "env_access",
               re.compile(r'getenv\s*\(|\$_ENV\s*\[|\$_SERVER\s*\[.*(HTTP_|REMOTE_|SERVER_)'), 10,
               "Environment/server variable access"),
    PHPPattern("sensitive", "serialize_unserialize",
               re.compile(r'unserialize\s*\(\s*\$'), 20,
               "Unserialize user input — object injection risk"),
]


# Files that are high-risk in WordPress context
WP_HIGH_RISK_FILES = {
    "wp-config.php", "wp-login.php", "wp-settings.php",
    ".htaccess", "index.php", "functions.php",
}

PHP_EXTENSIONS = {".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps"}


def is_php_file(filepath: str) -> bool:
    from pathlib import PurePosixPath
    return PurePosixPath(filepath).suffix.lower() in PHP_EXTENSIONS


def scan_php_line(line: str) -> List[Tuple[PHPPattern, str]]:
    """Scan a single PHP line against all patterns."""
    hits = []
    for pattern in PHP_PATTERNS:
        m = pattern.regex.search(line)
        if m:
            hits.append((pattern, m.group()))
    return hits
