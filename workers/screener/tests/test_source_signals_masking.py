"""Path-aware comment and string masking (#2457).

One C lexer applied to every file type failed in both directions: a Python
``'data/*.json'`` glob opened a block comment that erased the rest of the file,
while ``#`` comments in Python, shell and Dockerfiles stayed visible and became
confidence-1.0 malicious findings.
"""

from __future__ import annotations

import pytest

from ditto_screener.source_signals import (
    find_decisive_malicious_source,
    mask_comments,
    mask_string_literals,
)


def _blank(source: str, *fragments: str) -> str:
    """``source`` with each fragment blanked in place, line breaks kept."""
    for fragment in fragments:
        assert fragment in source, fragment
        source = source.replace(
            fragment, "".join(c if c == "\n" else " " for c in fragment)
        )
    return source


_PY = "g = glob.glob('data/*.json')  # see /* notes\nx = a // 2\n"
_PY_FSTRING = "#!/usr/bin/env python\ns = f'{open(p)} t' + r'''\n# x\n'''\n"
_SH = "echo \"a # b\" 'c # d' $# x#y # note\ncat `ls` # tail\n"
_DOCKER = "FROM x\n# mount /var/run/docker.sock\nRUN echo hi # later\n"
_RS = "fn f<'a>(s: &'a str) -> char { '\"' } // c\nlet u = \"http://x\";\n"
_TS = "const g = '/*'; // c\nconst u = `http://x`;\n"
_UNKNOWN = "// kept\n# kept\n'kept'\n"


@pytest.mark.parametrize(
    ("path", "source", "comments", "strings"),
    [
        (
            "src/agent.py",
            _PY,
            _blank(_PY, "# see /* notes"),
            _blank(_PY, "'data/*.json'"),
        ),
        (
            "src/agent.py",
            _PY_FSTRING,
            _PY_FSTRING,
            _blank(_PY_FSTRING, "f'", " t'", "r'''\n# x\n'''"),
        ),
        (
            "scripts/run.sh",
            _SH,
            _blank(_SH, "# note", "# tail"),
            _blank(_SH, '"a # b"', "'c # d'"),
        ),
        (
            "Dockerfile",
            _DOCKER,
            _blank(_DOCKER, "# mount /var/run/docker.sock", "# later"),
            _DOCKER,
        ),
        (
            "src/main.rs",
            _RS,
            _blank(_RS, "// c"),
            _blank(_RS, "'\"'", '"http://x"'),
        ),
        (
            "src/app.ts",
            _TS,
            _blank(_TS, "// c"),
            _blank(_TS, "'/*'", "`http://x`"),
        ),
        ("notes/readme.unknownext", _UNKNOWN, _UNKNOWN, _UNKNOWN),
    ],
)
def test_masking_follows_the_file_language_and_keeps_layout(
    path: str, source: str, comments: str, strings: str
) -> None:
    assert mask_comments(source, path) == comments
    assert mask_string_literals(source, path) == strings
    for masked in (comments, strings):
        assert len(masked) == len(source)
        assert len(masked.splitlines()) == len(source.splitlines())


@pytest.mark.parametrize(
    "path",
    ["src/agent.py", "run.sh", "Dockerfile", "src/main.rs", "src/app.ts", "x.bin"],
)
def test_masking_keeps_line_count_for_every_language(path: str) -> None:
    source = "a = 1 /* x\r\n# y ''' \"\"\" `\u2028// z\n'unterminated\n"
    for masked in (
        mask_comments(source, path),
        mask_string_literals(source, path),
    ):
        assert len(masked.splitlines()) == len(source.splitlines())


def test_unknown_or_missing_path_is_returned_unmasked() -> None:
    source = "// a\n/* b */\n# c\n'd'\n"
    assert mask_comments(source) == source
    assert mask_string_literals(source) == source
    assert mask_comments(source, "data.unknown") == source


def test_python_that_does_not_tokenize_falls_back_to_hash_comments() -> None:
    source = "def f(:\n    x = '/*' # c\n    y = a // 2\n"
    assert mask_comments(source, "src/agent.py") == (
        "def f(:\n    x = '/*'    \n    y = a // 2\n"
    )


@pytest.mark.parametrize(
    "literal", ["'x'", "'\\n'", "'\\u{1F600}'", "'\"'", "'/'", "'\\''"]
)
def test_rust_char_literals_do_not_desync_the_masker(literal: str) -> None:
    source = (
        f"fn pick<'a, 'b>(x: &'a str) -> char {{ {literal} }}\n"
        'let s = "// kept"; // gone\n'
        'let t = r#"*/"#; /* gone */ let u = 1;\n'
    )
    assert mask_comments(source, "src/lib.rs") == _blank(
        source, "// gone", "/* gone */"
    )
    masked = mask_string_literals(source, "src/lib.rs").splitlines()
    assert masked[0] == (
        f"fn pick<'a, 'b>(x: &'a str) -> char {{ {' ' * len(literal)} }}"
    )
    assert "kept" not in masked[1]


@pytest.mark.parametrize(
    ("path", "source"),
    [
        ("src/agent.py", "# never read ~/.ssh/id_rsa or .env files\nimport os\n"),
        (
            "Dockerfile",
            "FROM python:3.12\n# never mount /var/run/docker.sock\nRUN pip install x\n",
        ),
        ("scripts/run.sh", "#!/bin/sh\n# never cat ~/.ssh/id_rsa here\nexec agent\n"),
        (
            "src/lib.rs",
            "fn pick<'a>(x: &'a str) -> &'a str { x }\n"
            'const P: &str = "don\'t read ~/.ssh/id_rsa via std::fs::read";\n',
        ),
    ],
)
def test_prose_is_not_a_decisive_malicious_finding(path: str, source: str) -> None:
    assert (
        find_decisive_malicious_source(
            [(path, source)], explicitly_executable_paths=frozenset({path})
        )
        == []
    )


@pytest.mark.parametrize(
    ("path", "source", "category"),
    [
        (
            "src/agent.py",
            "import os\nkey = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n",
            "credential_access",
        ),
        (
            "src/agent.py",
            "n = a // 2; key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n",
            "credential_access",
        ),
        (
            "Dockerfile",
            "FROM x\nRUN curl --unix-socket /var/run/docker.sock http://d/info\n",
            "malicious_build",
        ),
        (
            "src/lib.rs",
            "fn pick<'a>(x: &'a str) -> &'a str { x }\n"
            'fn k() { std::fs::read("/home/u/.ssh/id_rsa"); }\n',
            "credential_access",
        ),
    ],
)
def test_executable_access_still_fires(path: str, source: str, category: str) -> None:
    findings = find_decisive_malicious_source(
        [(path, source)], explicitly_executable_paths=frozenset({path})
    )
    assert category in {finding["category"] for finding in findings}
