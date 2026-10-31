#!/usr/bin/env python3
"""Check English-script text, filenames, and local Markdown links.

This checks the repository's writing convention, not natural-language meaning.
Review prose manually as well. Binary evidence is preserved rather than edited.
Only tracked files and non-ignored additions belong to this audit.
"""
import re
import subprocess
import unicodedata
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'!?\[[^\]\n]*\]\(([^)\n]+)\)')
HEADING = re.compile(r'^#{1,6}\s+(.+?)\s*#*$', re.MULTILINE)


def non_latin_letters(text):
    return sorted({ch for ch in text if ord(ch) > 127 and ch.isalpha()
                   and 'LATIN' not in unicodedata.name(ch, '')})


def repository_files():
    output = subprocess.check_output(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT)
    return sorted({ROOT / name for name in output.decode().split('\0')
                   if name and (ROOT / name).is_file()})


def anchors(path):
    result = set()
    counts = {}
    for heading in HEADING.findall(path.read_text(encoding='utf-8')):
        slug = re.sub(r'[^\w\- ]', '', heading.lower()).replace(' ', '-')
        occurrence = counts.get(slug, 0)
        counts[slug] = occurrence + 1
        result.add(slug if not occurrence else f'{slug}-{occurrence}')
    return result


def main():
    issues = []
    text_count = 0
    binary_count = 0
    for path in repository_files():
        relative = path.relative_to(ROOT)
        if non_latin_letters(str(relative)):
            issues.append(f'{relative}: non-Latin letters in filename')
        try:
            content = path.read_text(encoding='utf-8')
        except UnicodeError:
            binary_count += 1
            continue
        if '\0' in content:
            binary_count += 1
            continue
        text_count += 1
        for number, line in enumerate(content.splitlines(), 1):
            letters = non_latin_letters(line)
            if letters:
                codes = ', '.join(f'U+{ord(ch):04X}' for ch in letters)
                issues.append(f'{relative}:{number}: non-Latin letters ({codes})')
        if path.suffix != '.md':
            continue
        for match in LINK.finditer(content):
            target = match.group(1).strip()
            if target.startswith('<') and target.endswith('>'):
                target = target[1:-1]
            if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:', target) or target.startswith('//'):
                continue
            link_path, _, fragment = target.partition('#')
            link_path = unquote(link_path.split('?', 1)[0])
            destination = (path.parent / link_path).resolve() if link_path else path
            if not destination.exists():
                issues.append(f'{relative}: missing link target {target}')
            elif fragment and destination.suffix == '.md' and unquote(fragment) not in anchors(destination):
                issues.append(f'{relative}: missing heading {target}')
    if issues:
        print('\n'.join(issues))
        raise SystemExit(1)
    print(f'Content checks passed: {text_count} text files, {binary_count} binary files; '
          'no non-Latin letters or broken local Markdown links.')


if __name__ == '__main__':
    main()
