#!/bin/bash
set -e
git fetch upstream
DEF=$(git remote show upstream | sed -n "s/.*HEAD branch: //p")
echo "上游最新($DEF): $(git log --oneline -1 upstream/$DEF)"
git rebase "upstream/$DEF" && echo "✅ 已同步" || echo "⚠️ 冲突,解决后 git add -A && git rebase --continue"