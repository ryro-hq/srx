"""Bound Syrox's cache history without deleting active or unrelated caches."""

import argparse
import datetime as dt
import json
import os
import re
import subprocess
from collections import defaultdict

OWNED = ("v0-rust-syrox-", "vm-linux-", "vm-prepare-v1-", "vm-vendor-v1-", "vm-compile-v2-")


def family(key):
    if key.startswith("v0-rust-syrox-"):
        match = re.fullmatch(r"(.+)-[a-f0-9]{8}-[a-f0-9]{8}", key)
        return match[1] if match else None
    for prefix in OWNED[1:]:
        if key.startswith(prefix):
            if prefix == "vm-linux-":
                match = re.fullmatch(r"(.+)-[a-f0-9]{64}", key)
                return match[1] if match else None
            # Vendor and compilation generations are bounded across lock changes.
            match = re.fullmatch(re.escape(prefix) + r"([A-Za-z0-9_]+)-[a-f0-9]{64}(?:-[a-f0-9]{40,64})?", key)
            return prefix + match[1] if match else None
    return None


def timestamp(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def deletion_plan(caches, default_branch, pull_request, active_runs, now, keep=2):
    """Keep open PRs, active refs, recent accesses and two main generations."""
    main = "refs/heads/" + default_branch
    active_refs = {"refs/heads/" + run["head_branch"] for run in active_runs if run.get("head_branch")}
    active_refs.update(
        f"refs/pull/{pr['number']}/merge"
        for run in active_runs for pr in run.get("pull_requests", [])
    )
    groups = defaultdict(list)
    decisions = []
    for cache in caches:
        group = family(cache["key"])
        if group is None:
            continue
        ref = cache["ref"]
        if ref == main:
            groups[group].append(cache)
            continue
        pr_ref = re.fullmatch(r"refs/pull/(\d+)/merge", ref)
        queue_ref = re.fullmatch(r"refs/heads/gh-readonly-queue/.+/pr-(\d+)-[a-f0-9]{40}", ref)
        match = pr_ref or queue_ref
        if not match:
            continue
        pr = pull_request(int(match[1]))
        if pr["state"] != "closed":
            continue
        # GitHub sometimes omits pull_requests from a workflow-run response.
        if any(run.get("head_sha") == pr["head"]["sha"] or run.get("head_branch") == pr["head"]["ref"] for run in active_runs):
            continue
        decisions.append((cache, "closed pull request or completed merge queue"))
    for values in groups.values():
        values.sort(key=lambda cache: timestamp(cache["created_at"]), reverse=True)
        decisions.extend((cache, "older default-branch generation") for cache in values[keep:])
    return [
        {"id": cache["id"], "key": cache["key"], "ref": cache["ref"], "bytes": cache["size_in_bytes"], "reason": reason}
        for cache, reason in decisions
        if cache["ref"] not in active_refs
        and now - timestamp(cache["last_accessed_at"]) >= dt.timedelta(hours=1)
    ]


def api(path, *, pages=False, delete=False):
    args = ["gh", "api", path]
    if pages:
        args += ["--paginate", "--slurp"]
    if delete:
        args += ["--method", "DELETE"]
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--apply", action="store_true", help="Delete the planned entries; default is read-only.")
    args = parser.parse_args()
    if not args.repo or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        parser.error("a valid owner/repository is required")
    base = "repos/" + args.repo
    repository = api(base)
    caches = [cache for page in api(base + "/actions/caches?per_page=100", pages=True) for cache in page["actions_caches"]]
    active = []
    for status in ["in_progress", "queued", "pending", "waiting"]:
        active.extend(run for page in api(base + f"/actions/runs?per_page=100&status={status}", pages=True) for run in page["workflow_runs"])
    prs = {}

    def pull_request(number):
        if number not in prs:
            prs[number] = api(base + f"/pulls/{number}")
        return prs[number]

    plan = deletion_plan(caches, repository["default_branch"], pull_request, active, dt.datetime.now(dt.timezone.utc))
    print(json.dumps({"apply": args.apply, "entries": plan, "reclaimed_bytes": sum(row["bytes"] for row in plan)}, indent=2))
    if args.apply:
        for row in plan:
            api(base + f"/actions/caches/{int(row['id'])}", delete=True)


if __name__ == "__main__":
    main()
