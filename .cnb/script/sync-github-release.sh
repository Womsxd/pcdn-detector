#!/usr/bin/env bash
# 把 GitHub 的 Release 同步到当前 CNB 仓库：
#   - 版本名（name）、描述（body）、预发布标记
#   - Release 附件（下载后上传，上传流程与 https://cnb.cool/womsxd/cnb-file-upload 一致）
#
# 三种用法：
#   1. 不带参数：同步 GitHub 最新 Tag 对应的 Release
#   2. RELEASE_TAG=<tag>：同步指定 Tag 的 Release
#   3. SYNC_TAGS="v1 v2"：逐个同步这些 Tag 的 Release（用于「Tag 有增加」的场景），
#      某个 Tag 在 GitHub 上没有 Release 时自动跳过，不判定为失败
#
# 依赖环境变量：
#   GITHUB_REPO          必填，GitHub 源仓库地址，如 https://github.com/Womsxd/pcdn-detector.git
#   GITHUB_REPO_SLUG     选填，owner/repo，地址较特殊时用于覆盖自动解析结果
#   GITHUB_TOKEN         选填，私有仓库 / 规避 API 限流
#   RELEASE_TAG          选填，指定同步的 Tag
#   SYNC_TAGS            选填，空格分隔的 Tag 列表
#   SYNC_RELEASE_ASSETS  选填，默认 true；false 时只同步版本名与描述
#   CNB_TOKEN / CNB_REPO_SLUG / CNB_API_ENDPOINT  由平台内置注入
#
# 用法：bash .cnb/script/sync-github-release.sh

set -euo pipefail

: "${GITHUB_REPO:?请通过环境变量 GITHUB_REPO 指定 GitHub 源仓库地址}"
: "${CNB_TOKEN:?缺少内置环境变量 CNB_TOKEN}"
: "${CNB_REPO_SLUG:?缺少内置环境变量 CNB_REPO_SLUG}"

CNB_API="${CNB_API_ENDPOINT:-https://api.cnb.cool}"
GH_API="${GITHUB_API_URL:-https://api.github.com}"
SYNC_RELEASE_ASSETS="${SYNC_RELEASE_ASSETS:-true}"
TARGET_REPO="${CNB_REPO_SLUG}"

# github.com/Womsxd/pcdn-detector(.git)、git@github.com:Womsxd/pcdn-detector(.git) -> Womsxd/pcdn-detector
GH_SLUG="${GITHUB_REPO_SLUG:-$(printf '%s' "${GITHUB_REPO%.git}" \
  | sed -E 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#^[^@/]+@##; s#^[^/:]+[:/]##' | sed 's#/*$##')}"
if ! printf '%s' "${GH_SLUG}" | grep -Eq '^[^/]+/[^/]+$'; then
  echo "❌ 无法从 GITHUB_REPO 解析出 owner/repo：${GITHUB_REPO}"
  echo "   如源仓库地址较特殊，可通过环境变量 GITHUB_REPO_SLUG 指定 owner/repo"
  exit 1
fi

GH_CURL=(-fsSL -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28")
if [ -n "${GITHUB_TOKEN:-}" ]; then
  GH_CURL+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

# 供 git fetch 使用的带凭据地址（日志中不打印）
GH_GIT_URL="${GITHUB_REPO}"
if [ -n "${GITHUB_TOKEN:-}" ]; then
  GH_GIT_URL="$(printf '%s' "${GITHUB_REPO}" | sed -E "s#^(https?://)#\\1cnb:${GITHUB_TOKEN}@#")"
fi

urlenc() { jq -rn --arg v "$1" '$v|@uri'; }

cnb_status() { # $1=url $2=响应体文件；回显 HTTP 状态码
  curl -sS -o "$2" -w '%{http_code}' \
    -H "Accept: application/vnd.cnb.api+json" \
    -H "Authorization: Bearer ${CNB_TOKEN}" "$1"
}

# ── 读取 GitHub 侧 Release ──────────────────────────────────────────────────
fetch_gh_release() { # $1=Tag（空则取最新）；输出 JSON 或空
  local tag="$1" out=""
  if [ -n "${tag}" ]; then
    echo "🔍 读取 GitHub Release: ${GH_SLUG}@${tag}" >&2
    out="$(curl "${GH_CURL[@]}" "${GH_API}/repos/${GH_SLUG}/releases/tags/$(urlenc "${tag}")" 2>/dev/null || true)"
  else
    echo "🔍 读取 GitHub 最新 Release: ${GH_SLUG}" >&2
    out="$(curl "${GH_CURL[@]}" "${GH_API}/repos/${GH_SLUG}/releases/latest" 2>/dev/null || true)"
    if [ -z "${out}" ] || [ "${out}" = "null" ]; then
      echo "ℹ️  /releases/latest 无结果（可能仅有预发布版本），回退到 Release 列表" >&2
      out="$(curl "${GH_CURL[@]}" "${GH_API}/repos/${GH_SLUG}/releases?per_page=30" 2>/dev/null \
        | jq -c '[.[] | select(.draft == false)] | .[0] // empty' || true)"
    fi
  fi
  if [ -z "${out}" ] || [ "${out}" = "null" ]; then
    printf ''
  else
    printf '%s' "${out}"
  fi
}

# ── 确保当前仓库存在指定 Tag（缺失时从 GitHub 单独拉取该 Tag） ──────────────
ensure_tag() { # $1=Tag
  local tag="$1" code=""
  code="$(cnb_status "${CNB_API}/${TARGET_REPO}/-/git/tags/$(urlenc "${tag}")" /tmp/cnb-tag.json)"
  if [ "${code}" = "200" ]; then
    echo "✅ 当前仓库已存在 Tag ${tag}"
    return 0
  fi

  echo "ℹ️  当前仓库尚无 Tag ${tag}（HTTP ${code}），尝试从 GitHub 补齐"
  : "${CNB_REPO_URL_HTTPS:?补齐 Tag 需要内置环境变量 CNB_REPO_URL_HTTPS}"
  local work
  work="$(mktemp -d)"
  (
    cd "${work}"
    git init -q .
    git remote add origin "${GH_GIT_URL}"
    git fetch -q --no-tags origin "+refs/tags/${tag}:refs/tags/${tag}"
    git push "${CNB_REPO_URL_HTTPS}" "refs/tags/${tag}:refs/tags/${tag}"
  )
  rm -rf "${work}"

  code="$(cnb_status "${CNB_API}/${TARGET_REPO}/-/git/tags/$(urlenc "${tag}")" /tmp/cnb-tag.json)"
  if [ "${code}" != "200" ]; then
    echo "❌ Tag ${tag} 补齐后仍不存在（HTTP ${code}）"
    return 1
  fi
  echo "✅ Tag ${tag} 已补齐"
}

# ── 创建或更新 Release（版本名 + 描述 + 预发布标记） ────────────────────────
upsert_release() { # $1=Tag $2=版本名 $3=描述 $4=prerelease；回显 release ID
  local tag="$1" name="$2" body="$3" pre="$4" code rel_id=""
  code="$(cnb_status "${CNB_API}/${TARGET_REPO}/-/releases/tags/$(urlenc "${tag}")" /tmp/cnb-release.json)"

  if [ "${code}" = "200" ]; then
    rel_id="$(jq -r '.id' /tmp/cnb-release.json)"
    local cur_name cur_body cur_pre
    cur_name="$(jq -r '.name // ""' /tmp/cnb-release.json)"
    cur_body="$(jq -r '.body // ""' /tmp/cnb-release.json)"
    cur_pre="$(jq -r '.prerelease // false' /tmp/cnb-release.json)"
    if [ "${cur_name}" = "${name}" ] && [ "${cur_body}" = "${body}" ] && [ "${cur_pre}" = "${pre}" ]; then
      echo "✅ Release ${tag} 的版本名与描述已一致，无需更新" >&2
    else
      echo "🔄 更新 Release ${tag} 的版本名与描述" >&2
      curl -fsSL -X PATCH "${CNB_API}/${TARGET_REPO}/-/releases/${rel_id}" \
        -H "Accept: application/vnd.cnb.api+json" \
        -H "Authorization: Bearer ${CNB_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$(jq -nc --arg n "${name}" --arg b "${body}" --argjson p "${pre}" \
               '{name: $n, body: $b, prerelease: $p}')" >/dev/null
      echo "✅ Release ${tag} 已更新" >&2
    fi
  else
    echo "➕ 创建 Release ${tag}" >&2
    curl -fsSL -X POST "${CNB_API}/${TARGET_REPO}/-/releases" \
      -H "Accept: application/vnd.cnb.api+json" \
      -H "Authorization: Bearer ${CNB_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$(jq -nc --arg t "${tag}" --arg n "${name}" --arg b "${body}" --argjson p "${pre}" \
             '{tag_name: $t, name: $n, body: $b, draft: false, prerelease: $p,
               make_latest: (if $p then "false" else "true" end)}')" >/tmp/cnb-release-created.json
    rel_id="$(jq -r '.id' /tmp/cnb-release-created.json)"
    echo "✅ Release ${tag} 已创建（ID=${rel_id}）" >&2
  fi
  printf '%s' "${rel_id}"
}

# ── 同步 Release 附件 ───────────────────────────────────────────────────────
# 上传流程同 cnb-file-upload：asset-upload-url 取预签名地址 -> PUT 上传 -> verify_url 确认。
# 注意：verify_url 必须带 Authorization 头，平台未登录时返回 401，附件不会落库。
# 这里直接用已解析出的 release ID，避免该脚本按 tag_name 过滤失效时传错版本。
sync_assets() { # $1=Release ID $2=GitHub Release JSON $3=Tag
  local rel_id="$1" gh_release="$2" tag="$3" exist_assets=""
  # 排除已有的 probe 探测临时附件，正常上传的附件仍为严格同名匹配
  cnb_status "${CNB_API}/${TARGET_REPO}/-/releases/${rel_id}" /tmp/cnb-release.json >/dev/null
  exist_assets="$(jq -r '.assets[]?.name' /tmp/cnb-release.json \
    | grep -vxF "probe-test.txt" | sort -u || true)"

  mkdir -p gh-assets
  local asset_name asset_url asset_size info upload_url verify_url
  while IFS=$'\t' read -r asset_name asset_url; do
    [ -n "${asset_name}" ] || continue
    if [ -n "${exist_assets}" ] && printf '%s\n' "${exist_assets}" | grep -qxF "${asset_name}"; then
      echo "⏭️  附件已存在，跳过: ${asset_name}"
      continue
    fi

    echo "⬇️  下载 GitHub 附件: ${asset_name}"
    curl -fsSL --retry 3 --retry-delay 2 -o "gh-assets/${asset_name}" "${asset_url}"
    asset_size="$(stat -c%s "gh-assets/${asset_name}")"
    echo "📤 上传附件到 CNB: ${asset_name} (${asset_size} bytes)"

    info="$(curl -fsSL -X POST "${CNB_API}/${TARGET_REPO}/-/releases/${rel_id}/asset-upload-url" \
      -H "Accept: application/vnd.cnb.api+json" \
      -H "Authorization: Bearer ${CNB_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$(jq -nc --arg n "${asset_name}" --argjson s "${asset_size}" \
             '{asset_name: $n, overwrite: true, size: $s}')")"

    upload_url="$(jq -r '.upload_url // ""' <<<"${info}")"
    verify_url="$(jq -r '.verify_url // ""' <<<"${info}")"
    if [ -z "${upload_url}" ] || [ "${upload_url}" = "null" ]; then
      echo "❌ 获取上传地址失败: ${info}"
      return 1
    fi

    local put_status=""
    put_status="$(curl -sS -X PUT "${upload_url}" -H "Accept: application/json" \
      -T "gh-assets/${asset_name}" -o /dev/null -w '%{http_code}')"
    if [ "${put_status}" != "200" ] && [ "${put_status}" != "201" ] && [ "${put_status}" != "204" ]; then
      echo "❌ 附件 ${asset_name} PUT 上传失败（HTTP ${put_status}）"
      return 1
    fi

    # 必须带 Authorization 调用 verify_url，否则平台返回 401，
    # 附件不会落库（Release 页看不到文件，下载 404）。
    if [ -z "${verify_url}" ] || [ "${verify_url}" = "null" ]; then
      echo "❌ 附件 ${asset_name} 缺少 verify_url，无法确认上传"
      return 1
    fi
    local verify_status=""
    verify_status="$(curl -sS -X POST "${verify_url}" \
      -H "Accept: application/json" \
      -H "Authorization: Bearer ${CNB_TOKEN}" \
      -o /dev/null -w '%{http_code}')"
    if [ "${verify_status}" != "200" ]; then
      echo "❌ 附件 ${asset_name} 上传确认失败（HTTP ${verify_status}）"
      return 1
    fi
    echo "✅ 附件上传完成: ${asset_name}"
  done < <(jq -r '.assets[]? | [.name, .browser_download_url] | @tsv' <<<"${gh_release}")

  echo "🎉 Release ${tag} 同步完成（版本名、描述、附件）"
}

# ── 同步单个 Tag 的 Release ─────────────────────────────────────────────────
# $1=Tag（空表示取 GitHub 最新）
sync_one_release() {
  local tag="$1" gh_release rel_id
  if ! gh_release="$(fetch_gh_release "${tag}")" || [ -z "${gh_release}" ]; then
    echo "ℹ️  ${GH_SLUG} 上没有 Tag ${tag:-<最新>} 对应的 Release，跳过"
    return 2
  fi

  local real_tag gh_name gh_body gh_pre
  real_tag="$(jq -r '.tag_name' <<<"${gh_release}")"
  gh_name="$(jq -r '.name // ""' <<<"${gh_release}")"
  gh_body="$(jq -r '.body // ""' <<<"${gh_release}")"
  gh_pre="$(jq -r '.prerelease // false' <<<"${gh_release}")"
  [ -n "${gh_name}" ] || gh_name="${real_tag}"
  echo "📦 目标版本: ${real_tag}（${gh_name}，prerelease=${gh_pre}）"

  ensure_tag "${real_tag}" || return 1
  rel_id="$(upsert_release "${real_tag}" "${gh_name}" "${gh_body}" "${gh_pre}")"

  if [ "${SYNC_RELEASE_ASSETS}" != "true" ]; then
    echo "⏭️  SYNC_RELEASE_ASSETS=${SYNC_RELEASE_ASSETS}，跳过附件同步"
    return 0
  fi
  sync_assets "${rel_id}" "${gh_release}" "${real_tag}" || return 1
}

main() {
  local tags="${SYNC_TAGS:-}" failed=0 skipped=0 rc=0

  # 未指定 Tag：同步 GitHub 最新 Release
  if [ -z "${tags}" ] && [ -z "${RELEASE_TAG:-}" ]; then
    sync_one_release "" || rc=$?
    if [ "${rc}" -gt 1 ]; then
      exit 1
    fi
    return 0
  fi

  # 指定了 Tag 列表：逐个同步，GitHub 上没有对应 Release 的 Tag 跳过、不计为失败
  local tag
  for tag in ${tags:-${RELEASE_TAG}}; do
    rc=0
    sync_one_release "${tag}" || rc=$?
    case "${rc}" in
      0) ;;
      2) skipped=$((skipped + 1)) ;;
      *) failed=$((failed + 1)) ;;
    esac
  done

  if [ "${failed}" -gt 0 ]; then
    echo "❌ 有 ${failed} 个 Release 同步失败"
    exit 1
  fi
  echo "ℹ️  本次处理完成（失败 0，无对应 Release 而跳过 ${skipped}）"
}

main
