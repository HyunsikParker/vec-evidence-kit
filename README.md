# VEC Evidence Kit

Offline packaging checks for Virtual Embryo Agent Team evidence. The tool freezes the input files you declare before a run, preserves a framework-exported trajectory byte for byte, and checks the resulting packet for changes, missing files and size limits. It uses the Python standard library; it downloads no data and calls no model or API.

## Try the synthetic example

Use Python 3.10 or newer. No installation is needed.

```sh
python3 vec_evidence.py lock --config examples/config.json --prompt examples/prompts.txt --harness examples/harness.py --out run.lock.json
python3 vec_evidence.py build --lock run.lock.json --trajectory examples/trajectory.jsonl --prediction examples/prediction.synthetic.txt --already-uploaded-bytes 0 --out packet
python3 vec_evidence.py check packet --prediction examples/prediction.synthetic.txt
```

The example is a packaging demonstration. Its trace, harness and prediction placeholder are synthetic: they are not a competition run, a biological result or an eligible prediction. The commands never execute the harness. Existing lock files and packet directories are not overwritten.

## Use it with a completed agent run

1. Put the actual framework and model identifiers, budget, tools and permissions in a JSON configuration. Include all prompts and harness source files with repeated `--prompt` and `--harness` arguments. Keep credentials out of the configuration. Run `lock` before starting the agent.
2. Run the agent through its own framework. Export that run's complete trajectory. This tool does not create, infer, repair or truncate a trajectory, and an ordinary stdout log is not automatically a complete framework trace.
3. Run `build` with that export and the prediction produced by the same run. It checks the frozen inputs, losslessly compresses the supplied trajectory, and records the prediction's SHA-256 without copying the prediction into the packet. `--already-uploaded-bytes` is required: use the team's actual existing evidence total, not an assumed zero.
4. Run `check` again before upload. Add `--prediction` to compare the current prediction bytes with the recorded digest. Review the full evidence for credentials and confidential content. Upload through the official portal yourself; this tool does not log in, register, submit or contact anyone.

The packet contains the supplied configuration, every declared prompt and harness file, the compressed trajectory, a portable lock and a manifest. Local source paths are omitted from the portable lock. Keep the original local lock and source files for your own records. Evidence belongs in the host's private submission flow, not in a public repository.

## What the checks mean

| Check | Result |
| --- | --- |
| Frozen inputs | A change to a declared configuration, prompt or harness file stops packaging. |
| Trajectory | Its decompressed bytes must match the captured length and SHA-256; a truncated or corrupt gzip fails. |
| Packet contents | Listed files are hashed; missing, extra, duplicate-path and symlink artifacts fail. |
| File and team size | Uses conservative decimal limits of 200,000,000 bytes per file and 600,000,000 bytes per team, including caller-declared previous uploads. Packet metadata is counted too. |
| Prediction | The manifest stores its byte count and SHA-256. `check --prediction FILE` verifies those bytes locally. |

The checker includes all three named prize-evidence kinds: trajectory, prompts and harness. It does not rely on the smaller evidence minimum for entering the scoring queue. Rules §9 and §14 distinguish those two requirements; the FAQ's queue wording currently differs from §9, so use the current rules rather than treating the FAQ as an exception.

A passing check is **not** proof of autonomy, complete run coverage, valid prediction format, official acceptance, a competition score or prize eligibility. The caller must supply the real run's complete evidence. Hashes detect changes relative to the recorded lock; someone who deliberately replaces the lock and manifest can manufacture new records. No timestamp authority or signature service is used.

The host's account state, prior uploads, permitted upload extensions and award decisions are not queried. Byte totals depend on the previous-upload amount supplied by the caller. Trajectory verification defaults to a 2 GB decompression limit; increase it with `--max-expanded-bytes` only for a known larger export. Hitting that limit fails the check without changing or truncating evidence.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The end-to-end suite uses generated synthetic bytes, including a multi-megabyte UTF-8 trace, modified locked files, a rehashed truncated gzip and a sparse file just above the 200 MB boundary. It makes no network requests and uses no competition data. macOS is tested; Windows and Linux execution have not been verified.

## Rule references and authorship

Requirements were checked on 4 October 2026 against the [official rules](https://virtualembryo.ai/challenge/rules), [terms](https://virtualembryo.ai/challenge/terms) and [community award page](https://virtualembryo.ai/challenge/community). Check the current rules before relying on the limits. This is an independent utility, not an organizer-approved tool.

Developed with AI assistance. The implementation and examples are original work in this repository; no competition datasets or participant predictions are included. MIT license.
