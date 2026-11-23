"""
Community patterns whose time grows with the cube of the value, and the linear patterns the
converters write instead.

Each is a token, any text, another token, and so on (`A.*B.*C`). The browser runs a rule's pattern
with JavaScript's RegExp, which backtracks: it tries the pattern again from each occurrence of the
first token, and the rest again from each occurrence of the second, so that a crafted value of
65,536 characters, as many as a rule's regular expression reads, holds the rules worker for hours.

Each linear pattern reads the value from its start, line by line (`^(?:[^\\n]*\\n)*`), and on a line
takes the first occurrence of each token, through classes that give each character one way to
match, so that a character is read a bounded number of times whatever the value. It matches the
values the upstream pattern matches in the store, whose RE2 reads `.` as any character but a
newline; the browser's engine also stops `.` at a carriage return and at the Unicode line and
paragraph separators, so there a value with one of those between the tokens is now matched as the
store matches it. tests/backend/test_linear_patterns.py and frontend/src/test/regexRewrites.test.ts
compare each with the pattern it replaces and time it.
"""

from __future__ import annotations

LINEAR: dict[str, str] = {
    # SigmaHQ "Windows Admin Share Mount Via Net.EXE": a space and two backslashes, then a backslash,
    # then a dollar sign; the first occurrence of " \\" on a line is found by a class for each state
    # of reading it (after a space, after a space and a backslash)
    r"\ \\\\.*\\.*\$": r"^(?:[^\n]*\n)*(?:[^ \n]| (?: |\\ )*\\?[^ \\\n])* (?: |\\ )*\\\\[^\\\n]*\\[^$\n]*\$",
    # SigmaHQ "Copy From Or To Admin Share Or Sysvol Folder": two backslashes, then a backslash, then a
    # dollar sign
    r"\\\\.*\\.*\$": r"^(?:[^\n]*\n)*(?:[^\\\n]|\\[^\\\n])*\\\\[^\\\n]*\\[^$\n]*\$",
    # Sublime "Service Abuse: ExactTarget with suspicious sender indicators": a bar, then one of the
    # words; the words are last, so the line after the first bar is read once from its end
    r".*\|.*(Manager|Careers|Recruitment|Specialist|Global)": r"^(?:[^\n]*\n)*[^|\n]*\|[^\n]*(Manager|Careers|Recruitment|Specialist|Global)",
}


def linear(pattern: str) -> str:
    """The linear form of a pattern that grows with the cube of the value; any other as it is."""
    return LINEAR.get(pattern, pattern)
