#!/usr/bin/env python3
"""Local integrity and packaging checks for Virtual Embryo agent evidence."""

import argparse
import contextlib
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone

VERSION = "0.1.0"
CHUNK = 1024 * 1024
FILE_LIMIT = 200_000_000  # Conservative decimal MB; not a server-side assertion.
TEAM_LIMIT = 600_000_000
EXPANDED_LIMIT = 2_000_000_000
METADATA_LIMIT = 128 * 1024
KINDS = {"configuration", "prompts", "harness", "trajectory", "lock"}


class EvidenceError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvidenceError("Metadata is not finite JSON") from exc


def digest(value):
    return hashlib.sha256(value).hexdigest()


@contextlib.contextmanager
def regular_file(path):
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    require(not path.is_symlink(), "Symlinks are not supported")
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "Expected a regular file")
        yield stream


def fingerprint(path, sink=None):
    """Stream bytes, rejecting a source that changed while it was read."""
    hasher = hashlib.sha256()
    count = 0
    with regular_file(path) as source:
        before = os.fstat(source.fileno())
        while block := source.read(CHUNK):
            hasher.update(block)
            count += len(block)
            if sink is not None:
                sink.write(block)
        after = os.fstat(source.fileno())
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
            and count == before.st_size, "Source changed during reading")
    return {"size_bytes": count, "sha256": hasher.hexdigest()}


def json_read(path):
    with regular_file(path) as source:
        payload = source.read(METADATA_LIMIT + 1)
    require(len(payload) <= METADATA_LIMIT, "JSON metadata exceeds 128 KiB")
    try:
        def reject_constant(value):
            raise ValueError("Non-finite JSON")

        def unique_keys(pairs):
            out = {}
            for key, value in pairs:
                if key in out:
                    raise ValueError("Duplicate JSON key")
                out[key] = value
            return out

        return json.loads(payload, parse_constant=reject_constant, object_pairs_hook=unique_keys)
    except (ValueError, UnicodeError) as exc:
        raise EvidenceError("Invalid JSON metadata") from exc


def json_write(path, value):
    body = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                      allow_nan=False).encode("utf-8") + b"\n"
    require(len(body) <= METADATA_LIMIT, "JSON metadata exceeds 128 KiB")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(body)


def validate_config(config):
    require(isinstance(config, dict), "Configuration must be a JSON object")
    for name in ("framework", "model"):
        require(isinstance(config.get(name), str) and bool(config[name].strip()),
                "Configuration must name a framework and model")
    canonical(config)

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                name = re.sub(r"[^a-z0-9]", "_", key.lower()).strip("_")
                sensitive = (name in {"password", "secret", "token", "authorization",
                                     "access_token", "refresh_token", "api_key"}
                             or name.endswith("_api_key") or name.endswith("_password"))
                require(not sensitive, "Do not put credentials in the configuration")
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(config)


def source_record(path):
    path = Path(path).absolute()
    record = fingerprint(path)
    require(record["size_bytes"] > 0, "An evidence input is empty")
    require(record["size_bytes"] <= FILE_LIMIT, "A locked input exceeds 200 MB")
    return {"source": str(path), "name": path.name, **record}


def portable_payload(payload):
    """Bind input bytes and declared config, without leaking local source paths."""
    sources = payload["sources"]
    def stripped(record):
        return {k: v for k, v in record.items() if k != "source"}
    return {
        "schema_version": payload["schema_version"], "created_at": payload["created_at"],
        "framework": payload["framework"], "model": payload["model"],
        "sources": {
            "configuration": stripped(sources["configuration"]),
            "prompts": [stripped(r) for r in sources["prompts"]],
            "harness": [stripped(r) for r in sources["harness"]],
        },
    }


def seal(payload):
    return {**payload, "lock_sha256": digest(canonical(portable_payload(payload)))}


def read_lock(path):
    locked = json_read(path)
    require(isinstance(locked, dict), "Invalid lock")
    unsigned = {k: v for k, v in locked.items() if k != "lock_sha256"}
    require(locked.get("schema_version") == 1
            and locked.get("lock_sha256") == digest(canonical(portable_payload(unsigned))),
            "Lock integrity check failed")
    sources = locked.get("sources")
    require(isinstance(sources, dict), "Invalid lock sources")
    require(isinstance(sources.get("configuration"), dict), "Missing configuration in lock")
    for kind in ("prompts", "harness"):
        require(isinstance(sources.get(kind), list) and bool(sources[kind]),
                "Lock needs prompts and harness files")
    for record in [sources["configuration"], *sources["prompts"], *sources["harness"]]:
        require(isinstance(record, dict) and isinstance(record.get("source"), str)
                and isinstance(record.get("name"), str)
                and type(record.get("size_bytes")) is int
                and 0 < record["size_bytes"] <= FILE_LIMIT
                and re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256"))),
                "Invalid locked input")
    return locked


def create_lock(config_path, prompt_paths, harness_paths, output):
    config = json_read(config_path)
    validate_config(config)
    payload = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "framework": config["framework"],
        "model": config["model"],
        "sources": {
            "configuration": source_record(config_path),
            "prompts": [source_record(p) for p in prompt_paths],
            "harness": [source_record(p) for p in harness_paths],
        },
    }
    require(payload["sources"]["prompts"] and payload["sources"]["harness"],
            "At least one prompt and one harness file are required")
    # Read twice so a config change between parsing and hashing is not accepted.
    require(json_read(config_path) == config, "Configuration changed during locking")
    locked = seal(payload)
    json_write(Path(output), locked)
    return {"operation": "lock", "lock_sha256": locked["lock_sha256"],
            "framework": config["framework"], "model": config["model"]}


def safe_name(name):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name) or "input"


def copy_locked(record, target, kind, relative):
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        actual = fingerprint(record["source"], sink=stream)
    require(actual == {k: record[k] for k in ("size_bytes", "sha256")},
            "A lock-bound input changed; start a new lock, do not repair the old run")
    return {"kind": kind, "path": relative, "input_name": record["name"], **actual}


def public_lock(locked):
    return {**portable_payload(locked), "lock_sha256": locked["lock_sha256"]}


def build_package(lock_path, trajectory, prediction, output, already_uploaded=0):
    require(type(already_uploaded) is int and 0 <= already_uploaded <= TEAM_LIMIT,
            "Prior team upload bytes must be between zero and 600 MB")
    locked = read_lock(lock_path)
    config = json_read(locked["sources"]["configuration"]["source"])
    validate_config(config)
    require(config["framework"] == locked["framework"] and config["model"] == locked["model"],
            "Framework/model changed since lock")
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), "Output already exists")
    require(output.parent.is_dir(), "Output parent directory does not exist")
    stage = Path(tempfile.mkdtemp(prefix=".vec-evidence-", dir=output.parent))
    try:
        files = [copy_locked(locked["sources"]["configuration"], stage / "config.json",
                             "configuration", "config.json")]
        for kind in ("prompts", "harness"):
            for index, record in enumerate(locked["sources"][kind], 1):
                relative = f"{kind}/{index:03d}-{safe_name(record['name'])}"
                files.append(copy_locked(record, stage / relative, kind, relative))
        fd = os.open(stage / "trajectory.gz", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as target:
            with gzip.GzipFile(fileobj=target, mode="wb", filename="", mtime=0) as compressed:
                raw = fingerprint(trajectory, sink=compressed)
        require(raw["size_bytes"] > 0, "Trajectory is empty")
        files.append({"kind": "trajectory", "path": "trajectory.gz",
                      **fingerprint(stage / "trajectory.gz"),
                      "uncompressed_size_bytes": raw["size_bytes"],
                      "uncompressed_sha256": raw["sha256"]})
        prediction_record = fingerprint(prediction)
        require(0 < prediction_record["size_bytes"] <= 1_200_000_000,
                "Prediction must be nonempty and no larger than 1,200 MB")
        json_write(stage / "lock.json", public_lock(locked))
        files.append({"kind": "lock", "path": "lock.json", **fingerprint(stage / "lock.json")})
        manifest = {
            "schema_version": 1, "tool_version": VERSION,
            "framework": locked["framework"], "model": locked["model"],
            "lock_sha256": locked["lock_sha256"],
            "already_uploaded_bytes": already_uploaded,
            "prediction": prediction_record,  # Digest only; prediction bytes are not copied.
            "files": files,
            "scope": "Local packaging/integrity checks only; no proof of autonomy, full run coverage, official format acceptance or score.",
        }
        json_write(stage / "manifest.json", manifest)
        report = check_package(stage, max_expanded=max(EXPANDED_LIMIT, raw["size_bytes"]))
        require(not output.exists() and not output.is_symlink(), "Output appeared during packaging")
        stage.rename(output)
        return {"operation": "build", **report}
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def confined_file(root, relative):
    require(isinstance(relative, str), "Invalid artifact path")
    name = PurePosixPath(relative)
    require(not name.is_absolute() and name.parts and all(x not in (".", "..") for x in name.parts)
            and "\\" not in relative and relative == name.as_posix(), "Unsafe artifact path")
    current = root
    for part in name.parts:
        current = current / part
        require(not current.is_symlink(), "Symlinks are not supported")
    require(current.resolve().is_relative_to(root.resolve()), "Artifact escaped package")
    return current


def check_package(package, max_expanded=EXPANDED_LIMIT, prediction=None):
    root = Path(package).absolute()
    require(root.is_dir() and not root.is_symlink(), "Package must be a real directory")
    require(type(max_expanded) is int and max_expanded > 0, "Expansion limit must be positive")
    manifest = json_read(root / "manifest.json")
    require(isinstance(manifest, dict) and manifest.get("schema_version") == 1,
            "Unsupported manifest")
    require(isinstance(manifest.get("files"), list) and bool(manifest["files"]), "No artifacts")
    for key in ("framework", "model"):
        require(isinstance(manifest.get(key), str) and manifest[key].strip(), "Missing framework/model")
    prior = manifest.get("already_uploaded_bytes")
    require(type(prior) is int and 0 <= prior <= TEAM_LIMIT, "Invalid prior team upload bytes")
    names = set()
    kinds = set()
    total = (root / "manifest.json").stat().st_size
    for record in manifest["files"]:
        require(isinstance(record, dict) and record.get("kind") in KINDS, "Invalid artifact kind")
        relative = record.get("path")
        require(relative not in names and relative != "manifest.json", "Duplicate artifact path")
        names.add(relative)
        kinds.add(record["kind"])
        actual_path = confined_file(root, relative)
        actual = fingerprint(actual_path)
        require(actual == {k: record.get(k) for k in ("size_bytes", "sha256")},
                "Artifact integrity mismatch")
        require(0 < actual["size_bytes"] <= FILE_LIMIT, "Artifact exceeds 200 MB or is empty")
        total += actual["size_bytes"]
        if record["kind"] == "trajectory":
            expected = record.get("uncompressed_size_bytes")
            require(type(expected) is int and 0 < expected <= max_expanded,
                    "Trajectory expansion exceeds the selected limit")
            hasher, count = hashlib.sha256(), 0
            with regular_file(actual_path) as packed:
                with gzip.GzipFile(fileobj=packed, mode="rb") as stream:
                    while block := stream.read(CHUNK):
                        count += len(block)
                        require(count <= expected, "Trajectory expanded beyond recorded length")
                        hasher.update(block)
            require(count == expected and hasher.hexdigest() == record.get("uncompressed_sha256"),
                    "Trajectory lossless-content check failed")
    require({"configuration", "prompts", "harness", "trajectory", "lock"} <= kinds,
            "Missing configuration, prompt, harness, trajectory or lock evidence")
    present = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    require(present == names | {"manifest.json"}, "Unlisted or missing package files")
    require(total + prior <= TEAM_LIMIT, "Package plus prior team evidence exceeds 600 MB")
    config = json_read(confined_file(root, "config.json"))
    validate_config(config)
    require(config["framework"] == manifest["framework"] and config["model"] == manifest["model"],
            "Framework/model metadata disagrees with configuration")
    locked = json_read(confined_file(root, "lock.json"))
    require(locked.get("lock_sha256") == manifest.get("lock_sha256")
            and locked.get("lock_sha256") == digest(canonical(portable_payload(locked))),
            "Packaged lock integrity mismatch")
    require(locked["framework"] == manifest["framework"] and locked["model"] == manifest["model"],
            "Framework/model metadata disagrees with lock")
    for kind in ("configuration", "prompts", "harness"):
        actual_inputs = [{"name": r.get("input_name"), "size_bytes": r["size_bytes"],
                          "sha256": r["sha256"]} for r in manifest["files"] if r["kind"] == kind]
        expected_inputs = locked["sources"][kind]
        if kind == "configuration":
            expected_inputs = [expected_inputs]
        require(actual_inputs == expected_inputs, "Packaged input differs from configuration lock")
    recorded_prediction = manifest.get("prediction")
    require(isinstance(recorded_prediction, dict)
            and type(recorded_prediction.get("size_bytes")) is int
            and 0 < recorded_prediction["size_bytes"] <= 1_200_000_000
            and re.fullmatch(r"[0-9a-f]{64}", str(recorded_prediction.get("sha256"))),
            "Invalid prediction digest metadata")
    if prediction is not None:
        require(fingerprint(prediction) == recorded_prediction, "Prediction differs from packaged digest")
    return {"check": "pass", "tool_version": VERSION, "evidence_kinds": sorted(kinds),
            "package_bytes": total, "already_uploaded_bytes": prior, "team_bytes_after": total + prior,
            "team_total_basis": "Local packet plus caller-declared prior uploads; host state not queried",
            "framework": manifest["framework"], "model": manifest["model"],
            "prediction_bytes_verified": prediction is not None,
            "official_autonomy_or_acceptance": "not verified"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    commands = parser.add_subparsers(dest="operation", required=True)
    lock = commands.add_parser("lock", help="Freeze configuration, prompts and harness before a run")
    lock.add_argument("--config", required=True)
    lock.add_argument("--prompt", action="append", required=True)
    lock.add_argument("--harness", action="append", required=True)
    lock.add_argument("--out", required=True)
    build = commands.add_parser("build", help="Package an existing real framework trajectory losslessly")
    build.add_argument("--lock", required=True)
    build.add_argument("--trajectory", required=True)
    build.add_argument("--prediction", required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--already-uploaded-bytes", type=int, required=True,
                       help="Evidence bytes already stored for the team; explicitly use 0 for a new team")
    check = commands.add_parser("check", help="Verify packet contents and conservative byte limits")
    check.add_argument("package")
    check.add_argument("--max-expanded-bytes", type=int, default=EXPANDED_LIMIT)
    check.add_argument("--prediction", help="Also compare the local prediction bytes to its stored digest")
    args = parser.parse_args(argv)
    try:
        if args.operation == "lock":
            result = create_lock(args.config, args.prompt, args.harness, args.out)
        elif args.operation == "build":
            result = build_package(args.lock, args.trajectory, args.prediction, args.out,
                                   args.already_uploaded_bytes)
        else:
            result = {"operation": "check", **check_package(args.package, args.max_expanded_bytes,
                                                              args.prediction)}
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
        return 0
    except (EvidenceError, OSError, EOFError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"check": "fail", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
