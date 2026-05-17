import io
import re
import tokenize
from pathlib import Path

ROOT = Path(r"d:\trae")
SKIP_DIRS = {"docs", ".venv", "__pycache__", ".git"}

def strip_python_comments_and_docstrings(source: str) -> str:
    out = []
    prev_toktype = tokenize.INDENT
    last_lineno = -1
    last_col = 0

    tokgen = tokenize.generate_tokens(io.StringIO(source).readline)
    for toktype, toktext, (slineno, scol), (elineno, ecol), _ in tokgen:
        if slineno > last_lineno:
            last_col = 0
        if scol > last_col:
            out.append(" " * (scol - last_col))

        if toktype == tokenize.COMMENT:
            pass
        elif toktype == tokenize.STRING and prev_toktype in (tokenize.INDENT, tokenize.NEWLINE):
            pass
        else:
            out.append(toktext)

        prev_toktype = toktype
        last_col = ecol
        last_lineno = elineno

    cleaned = "".join(out)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned

def main():
    changed = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue

        suffix = path.suffix.lower()
        if suffix == ".py":
            original = path.read_text(encoding="utf-8")
            cleaned = strip_python_comments_and_docstrings(original)
            if cleaned != original:
                path.write_text(cleaned, encoding="utf-8", newline="\n")
                changed.append(path)
        elif suffix == ".qss":
            original = path.read_text(encoding="utf-8")
            cleaned = re.sub(r"/\*.*?\*/", "", original, flags=re.S)
            cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
            if cleaned != original:
                path.write_text(cleaned, encoding="utf-8", newline="\n")
                changed.append(path)

    print(f"Changed files: {len(changed)}")
    for path in changed:
        print(path)

if __name__ == "__main__":
    main()
