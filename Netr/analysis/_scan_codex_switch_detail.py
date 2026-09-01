import json
from pathlib import Path
from datetime import datetime, timezone, timedelta

path = Path(r'C:\Users\VIENNA\.codex\sessions\2026\07\12\rollout-2026-07-12T16-30-16-019f5572-d3d9-70c2-87cd-f0ba2c77e401.jsonl')
switch_ts = '2026-07-18T04:52:33.430Z'

# collect around switch: last pre-grok user messages and first grok user/assistant + tool writes
pre_users = []
post_users = []
post_tools = []
settings_after = []
line_no = 0
seen_switch = False
with path.open('r', encoding='utf-8', errors='replace') as f:
    for line in f:
        line_no += 1
        try:
            obj = json.loads(line)
        except Exception:
            continue
        ts = obj.get('timestamp') or ''
        typ = obj.get('type')
        payload = obj.get('payload') or {}

        if typ == 'event_msg' and isinstance(payload, dict) and payload.get('type') == 'thread_settings_applied':
            model = (payload.get('thread_settings') or {}).get('model')
            if model == 'grok-4.5' and not seen_switch:
                seen_switch = True
                print('SWITCH LINE', line_no, ts, model)
            if ts >= '2026-07-18T04:50:00':
                settings_after.append((line_no, ts, model, (payload.get('thread_settings') or {}).get('model_provider_id')))

        # user messages
        if typ == 'response_item' and isinstance(payload, dict) and payload.get('type') == 'message' and payload.get('role') == 'user':
            content = payload.get('content') or []
            texts = []
            for c in content:
                if isinstance(c, dict) and c.get('type') in ('input_text','text') and c.get('text'):
                    texts.append(c['text'])
            text = '\n'.join(texts).strip()
            if not text:
                continue
            # skip huge system/agents preamble dumps
            if text.startswith('# AGENTS.md') or text.startswith('<permissions'):
                continue
            item = (line_no, ts, text[:500].replace('\n',' | '))
            if ts < switch_ts:
                pre_users.append(item)
                if len(pre_users) > 30:
                    pre_users = pre_users[-30:]
            else:
                if len(post_users) < 40:
                    post_users.append(item)

        # tool calls that write/edit after switch
        if ts >= switch_ts and typ == 'response_item' and isinstance(payload, dict):
            ptype = payload.get('type')
            if ptype in ('custom_tool_call','function_call','tool_call'):
                name = payload.get('name') or payload.get('tool_name') or ''
                args = payload.get('arguments') or payload.get('input') or payload.get('parameters') or ''
                if isinstance(args, dict):
                    args_s = json.dumps(args, ensure_ascii=False)[:300]
                else:
                    args_s = str(args)[:300]
                blob = (name + ' ' + args_s).lower()
                if any(k in blob for k in ['apply_patch','file_edit','file_write','edit_preview','write','hvvwatch','bridge.cpp','debugger_ui']):
                    if len(post_tools) < 80:
                        post_tools.append((line_no, ts, ptype, name, args_s.replace('\n',' ')[:280]))

print('\n=== last 15 user messages BEFORE grok-4.5 ===')
for ln, ts, text in pre_users[-15:]:
    print(f'L{ln} {ts}\n  {text}\n')

print('=== first 20 user messages AFTER grok-4.5 ===')
for ln, ts, text in post_users[:20]:
    print(f'L{ln} {ts}\n  {text}\n')

print('=== settings around switch ===')
for row in settings_after[:20]:
    print(row)

print('=== tool writes after switch (sample) ===')
for row in post_tools[:40]:
    print(row[0], row[1], row[3], row[4][:200])

print('counts pre_users_kept', len(pre_users), 'post_users', len(post_users), 'post_tools', len(post_tools))
