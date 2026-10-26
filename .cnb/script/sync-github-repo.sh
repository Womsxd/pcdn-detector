#!/usr/bin/env bash
# 把 GITHUB_REPO 的分支与 Tag 同步到当前 CNB 仓库，
# 并检测本次同步是否新增了 Tag，结果通过 ##[set-output tags_added=...] 输出，
# 供后续 Stage 判断是否需要同步 Release。
#
# 依赖环境变量：
#   GITHUB_REPO          必填，GitHub 源仓库地址，如 https://github.com/Womsxd/pcdn-detector.git
#   GITHUB_TOKEN         选填，私有仓库或需要规避 API 限流时使用
#   CNB_TOKEN / CNB_REPO_SLUG / CNB_REPO_URL_HTTPS  由平台内置注入
#
# 用法：bash .cnb/script/sync-github-repo.sh

set -euo pipefail

: "${GITHUB_REPO:?请通过环境变量 GITHUB_REPO 指定 GitHub 源仓库地址}"
: "${CNB_REPO_URL_HTTPS:?缺少内置环境变量 CNB_REPO_URL_HTTPS}"
: "${CNB_REPO_SLUG:?缺少内置环境变量 CNB_REPO_SLUG}"

GH_URL="${GITHUB_REPO}"
if [ -n "${GITHUB_TOKEN:-}" ]; then
  # 注入凭据以支持私有仓库，日志中不打印该地址
  GH_URL="$(printf '%s' "${GITHUB_REPO}" | sed -E "s#^(https?://)#\1cnb:${GITHUB_TOKEN}@#")"
fi

# Tag 快照：优先使用仓库自身的 git 远端信息，失败时回退 CNB OpenAPI
list_tags_git() {
  git ls-remote --tags "${CNB_REPO_URL_HTTPS}" 2>/dev/null \
    | awk '{print $2}' | sed -e 's#^refs/tags/##' -e 's#\^{}$##' | sort -u
}

list_tags_api() {
  local page=1 names="" chunk=""
  while :; do
    chunk="$(curl -fsSL 2>/dev/null -H "Accept: application/vnd.cnb.api+json" \
      -H "Authorization: Bearer ${CNB_TOKEN}" \
      "${CNB_API_ENDPOINT:-https://api.cnb.cool}/${CNB_REPO_SLUG}/-/git/tags?page=${page}&page_size=100" \
      | jq -r '.[]? | .name')" || return 1
    [ -n "${chunk}" ] || break
    names="${names}${chunk}"$'\n'
    [ "$(printf '%s\n' "${chunk}" | grep -c .)" -lt 100 ] && break
    page=$((page + 1))
  done
  printf '%s' "${names}" | sort -u
}

list_tags() {
  local out=""
  out="$(list_tags_git || true)"
  if [ -z "${out}" ]; then
    out="$(list_tags_api || true)"
  fi
  printf '%s' "${out}"
}

count_lines() { printf '%s\n' "$1" | grep -c . || true; }

before="$(list_tags)"
echo "ℹ️ 同步前当前仓库 Tag 数量: $(count_lines "${before}")"

echo "🔄 开始同步 ${GITHUB_REPO} -> ${CNB_REPO_URL_HTTPS}"
rm -rf syncRepo
git clone --bare "${GH_URL}" syncRepo
(
  cd syncRepo
  git push --prune "${CNB_REPO_URL_HTTPS}" \
    '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*'
)

after="$(list_tags)"
echo "ℹ️ 同步后当前仓库 Tag 数量: $(count_lines "${after}")"

new_tags="$(comm -13 <(printf '%s\n' "${before}" | sed '/^$/d') \
                     <(printf '%s\n' "${after}"  | sed '/^$/d'))"

if [ -n "${new_tags}" ]; then
  echo "🆕 检测到新增 Tag: $(printf '%s' "${new_tags}" | tr '\n' ' ')"
  echo "##[set-output tags_added=true]"
  # 以空格分隔的 Tag 列表，供 sync_release 逐个检测是否需要同步 Release
  echo "##[set-output tags_added_list=$(printf '%s' "${new_tags}" | tr '\n' ' ' | sed -e 's/ *$//')]"
else
  echo "ℹ️ 本次同步未新增 Tag，无需检测 Release 同步"
  echo "##[set-output tags_added=false]"
  echo "##[set-output tags_added_list=]"
fi
