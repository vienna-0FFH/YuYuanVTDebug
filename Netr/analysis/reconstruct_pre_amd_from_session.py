import argparse
import json
import os
from pathlib import Path, PurePosixPath


BEGIN = "*** Begin Patch"
END = "*** End Patch"
AMBIGUITIES = []
ALREADY_REVERSED = []
DEFERRED_CONTEXT_FREE_DELETIONS = []


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", required=True)
    parser.add_argument("--staging", required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--only-file")
    return parser.parse_args()


def flatten_output(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(flatten_output(item) for item in value)
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            return value["text"]
        return "\n".join(flatten_output(item) for item in value.values())
    return ""


def unescape_javascript(raw):
    output = []
    index = 0
    simple = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "b": "\b",
        "f": "\f",
        "v": "\v",
        "0": "\0",
        "\\": "\\",
        "\"": "\"",
        "'": "'",
        "`": "`",
    }
    while index < len(raw):
        char = raw[index]
        if char != "\\":
            output.append(char)
            index += 1
            continue
        index += 1
        if index >= len(raw):
            raise ValueError("unterminated JavaScript escape")
        escaped = raw[index]
        if escaped in simple:
            output.append(simple[escaped])
            index += 1
        elif escaped == "x":
            output.append(chr(int(raw[index + 1:index + 3], 16)))
            index += 3
        elif escaped == "u":
            output.append(chr(int(raw[index + 1:index + 5], 16)))
            index += 5
        elif escaped == "\n":
            index += 1
        elif escaped == "\r":
            index += 1
            if index < len(raw) and raw[index] == "\n":
                index += 1
        else:
            output.append(escaped)
            index += 1
    return "".join(output)


def extract_patch_envelopes(tool_input):
    envelopes = []
    cursor = 0
    while True:
        begin = tool_input.find(BEGIN, cursor)
        if begin < 0:
            break
        end = tool_input.find(END, begin)
        if end < 0:
            raise ValueError("patch envelope has no end marker")
        raw = tool_input[begin:end + len(END)]
        envelopes.append(unescape_javascript(raw))
        cursor = end + len(END)
    return envelopes


def normalize_workspace_path(value):
    path = value.strip().replace("\\", "/")
    marker = "/YuYuanVTDebug/"
    lowered = path.lower()
    marker_index = lowered.find(marker.lower())
    if marker_index >= 0:
        path = path[marker_index + len(marker):]
    path = str(PurePosixPath(path))
    if not path.startswith("Netr/"):
        return None
    excluded = (
        "Netr/analysis/",
        "Netr/test-package/",
        "Netr/x64/",
        "Netr/cert/",
    )
    if path.startswith(excluded):
        return None
    if any(part in {"node_modules", "target", "dist", "bin", "obj"}
           for part in PurePosixPath(path).parts):
        return None
    return path


def parse_sections(envelope):
    lines = envelope.splitlines()
    if not lines or lines[0] != BEGIN or lines[-1] != END:
        raise ValueError("invalid patch envelope")
    sections = []
    index = 1
    while index < len(lines) - 1:
        line = lines[index]
        prefixes = {
            "*** Update File: ": "update",
            "*** Add File: ": "add",
            "*** Delete File: ": "delete",
        }
        operation = None
        source = None
        for prefix, candidate in prefixes.items():
            if line.startswith(prefix):
                operation = candidate
                source = line[len(prefix):]
                break
        if operation is None:
            raise ValueError(f"unexpected patch line: {line!r}")
        index += 1
        move_to = None
        if index < len(lines) - 1 and lines[index].startswith("*** Move to: "):
            move_to = lines[index][len("*** Move to: "):]
            index += 1
        body = []
        while index < len(lines) - 1 and not lines[index].startswith(
            ("*** Update File: ", "*** Add File: ", "*** Delete File: ")
        ):
            body.append(lines[index])
            index += 1
        sections.append({
            "operation": operation,
            "source": source,
            "move_to": move_to,
            "body": body,
        })
    return sections


def decode_file(path):
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8"), "utf-8-sig"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("cp1252"), "cp1252"


def encode_file(path, text, encoding):
    if encoding == "utf-8-sig":
        path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
    else:
        path.write_bytes(text.encode(encoding))


def sequence_matches(lines, sequence):
    if not sequence:
        return []
    matches = []
    limit = len(lines) - len(sequence) + 1
    for index in range(max(limit, 0)):
        if lines[index:index + len(sequence)] == sequence:
            matches.append(index)
    return matches


def find_sequence(lines, sequence):
    matches = sequence_matches(lines, sequence)
    if not matches:
        preview = " | ".join(sequence[:6])
        raise ValueError(
            f"expected a reverse hunk match; sequence={preview!r}"
        )
    if len(matches) > 1:
        AMBIGUITIES.append({
            "matches": matches,
            "selected": matches[-1],
            "sequence": sequence[:6],
        })
    return matches[-1]


def parse_hunks(body):
    hunks = []
    current = None
    header = None
    for line in body:
        if line.startswith("@@"):
            current = []
            header = line
            hunks.append((header, current))
            continue
        if line == "*** End of File" or line.startswith("\\ No newline"):
            continue
        if current is None:
            raise ValueError(f"update body before hunk header: {line!r}")
        if not line or line[0] not in " +-":
            raise ValueError(f"invalid hunk line: {line!r}")
        current.append(line)
    return hunks


def reverse_update(path, body):
    text, encoding = decode_file(path)
    eol = "\r\n" if text.count("\r\n") >= max(text.count("\n") // 2, 1) else "\n"
    trailing_newline = text.endswith(("\n", "\r"))
    lines = text.splitlines()
    for header, hunk in reversed(parse_hunks(body)):
        forward_new = [line[1:] for line in hunk if line[0] in " +"]
        forward_old = [line[1:] for line in hunk if line[0] in " -"]
        if not forward_new:
            DEFERRED_CONTEXT_FREE_DELETIONS.append({
                "path": str(path),
                "header": header,
                "deleted": forward_old[:6],
            })
            continue
        try:
            position = find_sequence(lines, forward_new)
        except Exception as error:
            old_matches = sequence_matches(lines, forward_old)
            if old_matches:
                ALREADY_REVERSED.append({
                    "path": str(path),
                    "header": header,
                    "matches": old_matches,
                })
                continue
            raise ValueError(f"{path}: {header}: {error}") from error
        lines[position:position + len(forward_new)] = forward_old
    result = eol.join(lines)
    if trailing_newline:
        result += eol
    encode_file(path, result, encoding)


def reverse_section(staging, section, only_file=None):
    source_relative = normalize_workspace_path(section["source"])
    move_relative = normalize_workspace_path(section["move_to"]) if section["move_to"] else None
    if source_relative is None and move_relative is None:
        return None
    selected_relative = move_relative or source_relative
    if only_file and selected_relative != only_file:
        return None
    source = staging / Path(source_relative)
    current = staging / Path(move_relative) if move_relative else source
    operation = section["operation"]
    if operation == "add":
        if not current.is_file():
            raise FileNotFoundError(f"added file is absent during reverse: {current}")
        current.unlink()
    elif operation == "delete":
        raise ValueError(f"cannot reverse content-free delete: {source_relative}")
    else:
        if not current.is_file():
            raise FileNotFoundError(f"updated file is absent during reverse: {current}")
        reverse_update(current, section["body"])
    if move_relative:
        source.parent.mkdir(parents=True, exist_ok=True)
        current.replace(source)
    return source_relative or move_relative


def main():
    args = parse_args()
    staging = Path(args.staging).resolve()
    if not (staging / "Netr" / "HvVwatch.c").is_file():
        raise SystemExit("staging root is missing Netr/HvVwatch.c")

    calls = []
    outputs = {}
    with open(args.session, "r", encoding="utf-8") as session:
        for raw_line in session:
            record = json.loads(raw_line)
            payload = record.get("payload", {})
            if payload.get("type") == "custom_tool_call_output":
                outputs[payload.get("call_id")] = flatten_output(payload.get("output"))
                continue
            if not (args.start <= record.get("timestamp", "") <= args.end):
                continue
            if payload.get("type") != "custom_tool_call" or payload.get("name") != "exec":
                continue
            tool_input = payload.get("input", "")
            if "tools.apply_patch" not in tool_input:
                continue
            calls.append({
                "timestamp": record["timestamp"],
                "call_id": payload.get("call_id"),
                "input": tool_input,
            })

    changed = []
    skipped_failed = []
    skipped_dynamic_analysis = []
    applied_calls = 0
    for call in reversed(calls):
        output = outputs.get(call["call_id"], "")
        if not output or "Script failed" in output:
            skipped_failed.append(call["call_id"])
            continue
        envelopes = extract_patch_envelopes(call["input"])
        call_changed = False
        for envelope in reversed(envelopes):
            try:
                sections = parse_sections(envelope)
            except Exception as error:
                if "Netr/analysis/amd_svm_tf_transaction_rollback_2026-07-24.patch" in call["input"]:
                    skipped_dynamic_analysis.append(call["call_id"])
                    continue
                raise RuntimeError(
                    f"patch parse failed at {call['timestamp']} "
                    f"{call['call_id']}: {error}"
                ) from error
            for section in reversed(sections):
                try:
                    relative = reverse_section(staging, section, args.only_file)
                except Exception as error:
                    raise RuntimeError(
                        f"reverse failed at {call['timestamp']} {call['call_id']} "
                        f"{section['operation']} {section['source']}: {error}"
                    ) from error
                if relative:
                    changed.append(relative)
                    call_changed = True
        if call_changed:
            applied_calls += 1

    report = {
        "start": args.start,
        "end": args.end,
        "only_file": args.only_file,
        "candidate_calls": len(calls),
        "applied_product_calls": applied_calls,
        "changed_operations": len(changed),
        "changed_files": sorted(set(changed)),
        "skipped_failed_calls": skipped_failed,
        "skipped_dynamic_analysis_calls": skipped_dynamic_analysis,
        "reverse_order_ambiguities": AMBIGUITIES,
        "already_reversed_hunks": ALREADY_REVERSED,
        "deferred_context_free_deletions": DEFERRED_CONTEXT_FREE_DELETIONS,
    }
    Path(args.report).write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
