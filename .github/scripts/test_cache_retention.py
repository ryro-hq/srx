import datetime as dt
import unittest
import contextlib
import io
from unittest.mock import patch
import cache_retention
from cache_retention import deletion_plan, family


NOW = dt.datetime(2026, 10, 14, 12, tzinfo=dt.timezone.utc)
KEY = "vm-compile-v2-Linux-" + "a" * 64 + "-" + "b" * 64


def cache(number, ref="refs/heads/main", age=2, key=KEY):
    time = (NOW - dt.timedelta(hours=age)).isoformat()
    return {"id": number, "key": key, "ref": ref, "created_at": time, "last_accessed_at": time, "size_in_bytes": 100}


def closed(_number):
    return {"state": "closed", "head": {"sha": "c" * 40, "ref": "topic"}}


class CacheRetention(unittest.TestCase):
    def test_closed_pr_and_queue_caches_are_reclaimed(self):
        rows = [cache(1, "refs/pull/3/merge"), cache(2, "refs/heads/gh-readonly-queue/main/pr-3-" + "d" * 40)]
        self.assertEqual([row["id"] for row in deletion_plan(rows, "main", closed, [], NOW)], [1, 2])

    def test_open_pr_and_unrelated_caches_are_untouched(self):
        rows = [cache(1, "refs/pull/3/merge"), cache(2, "refs/pull/3/merge", key="codeql-overlay-other"), cache(3, "refs/heads/topic")]
        self.assertEqual(deletion_plan(rows, "main", lambda _: {"state": "open"}, [], NOW), [])

    def test_two_main_generations_survive_across_lock_changes(self):
        rows = [cache(1, age=2), cache(2, age=3, key=KEY.replace("a", "e")), cache(3, age=4)]
        self.assertEqual([row["id"] for row in deletion_plan(rows, "main", closed, [], NOW)], [3])

    def test_recently_accessed_cache_survives(self):
        self.assertEqual(deletion_plan([cache(1, "refs/pull/3/merge", age=0.5)], "main", closed, [], NOW), [])

    def test_active_pr_survives_even_if_github_omits_pr_numbers(self):
        rows = [cache(1, "refs/pull/3/merge")]
        for run in [{"head_sha": "c" * 40}, {"head_branch": "topic"}, {"pull_requests": [{"number": 3}]}]:
            self.assertEqual(deletion_plan(rows, "main", closed, [run], NOW), [])

    def test_active_queue_and_main_refs_survive(self):
        queue = "gh-readonly-queue/main/pr-3-" + "d" * 40
        rows = [cache(1, "refs/heads/" + queue), cache(2, age=2), cache(3, age=3), cache(4, age=4)]
        self.assertEqual(deletion_plan(rows, "main", closed, [{"head_branch": queue}, {"head_branch": "main"}], NOW), [])

    def test_unknown_key_formats_are_not_deleted(self):
        self.assertIsNone(family("v0-rust-syrox-new-format"))
        self.assertIsNone(family("vm-compile-v2-Linux-unrecognized"))

    def test_remote_api_is_read_only_without_apply(self):
        calls = []
        row = cache(1, "refs/pull/3/merge")
        row["last_accessed_at"] = "2000-01-01T00:00:00Z"

        def fake(path, *, pages=False, delete=False):
            calls.append((path, delete))
            if path == "repos/ryro-hq/syrox":
                return {"default_branch": "main"}
            if "/actions/caches?" in path:
                return [{"actions_caches": [row]}]
            if "/actions/runs?" in path:
                return [{"workflow_runs": []}]
            if "/pulls/" in path:
                return closed(3)
            return None

        with patch.object(cache_retention, "api", side_effect=fake), patch("sys.argv", ["cache_retention", "--repo", "ryro-hq/syrox"]), contextlib.redirect_stdout(io.StringIO()):
            cache_retention.main()
        self.assertFalse(any(delete for _, delete in calls))
        calls.clear()
        with patch.object(cache_retention, "api", side_effect=fake), patch("sys.argv", ["cache_retention", "--repo", "ryro-hq/syrox", "--apply"]), contextlib.redirect_stdout(io.StringIO()):
            cache_retention.main()
        self.assertEqual([path for path, delete in calls if delete], ["repos/ryro-hq/syrox/actions/caches/1"])

    def test_metadata_failure_prevents_deletion(self):
        with patch.object(cache_retention, "api", side_effect=RuntimeError("API unavailable")) as api, patch("sys.argv", ["cache_retention", "--repo", "ryro-hq/syrox", "--apply"]):
            with self.assertRaises(RuntimeError):
                cache_retention.main()
        self.assertFalse(any(call.kwargs.get("delete") for call in api.call_args_list))


if __name__ == "__main__":
    unittest.main()
