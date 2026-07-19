#!/usr/bin/env bash
# Fix D-004: remove generated files that were committed before .gitignore
# existed (the repo previously had ".gitignore.txt", which git ignores).
#
# This stops tracking build artifacts, databases, and bytecode WITHOUT
# deleting your local copies. Run from the repo root, then commit.
set -euo pipefail

# delete the old, ineffective file if present
git rm --cached --ignore-unmatch .gitignore.txt 2>/dev/null || true

# untrack generated artifacts (keeps them on disk with --cached)
git rm -r --cached --ignore-unmatch \
    build/ \
    '*.so' '*.dylib' '*.dll' '*.o' '*.obj' \
    '*.db' '*.dat' \
    '*.pyc' __pycache__/ 2>/dev/null || true

echo
echo "Untracked generated files. Now run:"
echo "  git add .gitignore"
echo "  git commit -m \"Fix D-004: add proper .gitignore, untrack build artifacts and databases\""
echo
echo "Note: this removes them from future commits but not from past history."
echo "For a class project that's fine. To purge from history entirely, use"
echo "git-filter-repo — but coordinate with your team first, it rewrites history."
