"""Every nginx configuration example of README.md and example.conf passes nginx -t.

The examples use placeholders that cannot work here as written, so a few are
replaced before the check:

- host names under example.com: nginx resolves the host of every "url" when
  it reads the configuration, so they become the host of the test directory;
- files under /etc/nginx/ldap/ (CA certificates, included files) live in the
  prefix of the test instance;
- "load_module" lines are dropped: the module is built into the test binary;
- "include mime.types" finds a stub file.

Credentials are not replaced: nginx -t does not connect to the server.

A README block is checked as a complete nginx.conf when it has an "events"
block, and as the content of the http block otherwise. A block whose first
line is a comment naming a file under /etc/nginx/ldap/ is that file: it is
written there and checked through the examples that include it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from harness import NGINX_BINARY, Nginx
from ldapdata import LDAP_HOST, TLS_DIR

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
EXAMPLE_CONF = ROOT / "example.conf"

NGINX_BLOCK_RE = re.compile(r"^```nginx\n(.*?)^```$", re.MULTILINE | re.DOTALL)
FILE_BLOCK_RE = re.compile(r"\A# (/etc/nginx/ldap/\S+)\n")
EXAMPLE_HOST_RE = re.compile(r"\b[a-z0-9-]+\.example\.com\b")
LOAD_MODULE_RE = re.compile(r"^\s*load_module\s+\S*ngx_http_auth_ldap_module\.so;\n", re.MULTILINE)
EVENTS_RE = re.compile(r"^\s*events\s*\{", re.MULTILINE)
FILES_DIR = "/etc/nginx/ldap/"


def readme_blocks() -> list[tuple[int, str]]:
    """(line number, text) of every ```nginx block of README.md."""
    text = README.read_text()
    return [
        (text.count("\n", 0, match.start()) + 2, match.group(1)) for match in NGINX_BLOCK_RE.finditer(text)
    ]


def file_blocks() -> dict[str, str]:
    """README blocks that are files included by other examples, by path."""
    files = {}
    for _, block in readme_blocks():
        match = FILE_BLOCK_RE.match(block)
        if match is not None:
            files[match.group(1)] = block
    return files


def examples() -> list:
    params = [
        pytest.param(block, id=f"README.md:{line}")
        for line, block in readme_blocks()
        if FILE_BLOCK_RE.match(block) is None
    ]
    params.append(pytest.param(EXAMPLE_CONF.read_text(), id="example.conf"))
    return params


def localize(text: str, files_dir: Path) -> str:
    text = EXAMPLE_HOST_RE.sub(LDAP_HOST, text)
    text = LOAD_MODULE_RE.sub("", text)
    return text.replace(FILES_DIR, f"{files_dir}/")


def prepare_files(nginx: Nginx) -> Path:
    """The files the examples refer to, in the prefix of the instance."""
    files_dir = nginx.prefix / "ldap"
    (files_dir / "certs").mkdir(parents=True, exist_ok=True)
    shutil.copy(TLS_DIR / "ca.crt", files_dir / "ca.pem")
    shutil.copy(TLS_DIR / "ca.crt", files_dir / "certs" / "ca.pem")
    for path, block in file_blocks().items():
        (files_dir / path.removeprefix(FILES_DIR)).write_text(localize(block, files_dir))
    return files_dir


def nginx_t(nginx: Nginx, config: str) -> subprocess.CompletedProcess:
    # Creates the prefix directories; replaced below for a complete file.
    nginx.write_config()
    files_dir = prepare_files(nginx)
    (nginx.prefix / "conf" / "mime.types").write_text("types {\n    text/html html;\n}\n")
    config = localize(config, files_dir)
    if EVENTS_RE.search(config):
        nginx.conf_path.write_text(config)
    else:
        nginx.write_config(http=config)
    return subprocess.run(
        [NGINX_BINARY, "-t", "-p", str(nginx.prefix), "-c", str(nginx.conf_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_readme_has_nginx_examples():
    # Guards the parametrized test: without ```nginx blocks it checks nothing.
    assert len(readme_blocks()) >= 10


def test_readme_includes_only_files_it_shows():
    shown = set(file_blocks())
    included = set(re.findall(r"include\s+(/etc/nginx/ldap/\S+);", README.read_text()))

    assert included <= shown


@pytest.mark.parametrize("config", examples())
def test_example_passes_nginx_t(nginx, config):
    result = nginx_t(nginx, config)

    # A negative return code means nginx -t was killed by a signal.
    assert result.returncode == 0, f"nginx -t exited with {result.returncode}:\n{result.stderr}\n{config}"
