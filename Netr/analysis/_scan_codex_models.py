import json
from pathlib import Path
from collections import Counter, OrderedDict

paths = [
    Path(r'C:\Users\VIENNA\.codex\sessions\2026\07\12\rollout-2026-07-12T16-30-16-019f5572-d3d9-70c2-87cd-f0ba2c77e401.jsonl'),
    Path(r'C:\Users\VIENNA\.codex\sessions\2026\07\17\rollout-2026-07-17T12-36-28-019f6e5c-9233-7b12-80b4-dc5d7f77b252.jsonl'),
]
# also include latest forks under 07/17 that may continue main work
for p in sorted(Path(r'C:\Users\VIENNA\.codex\sessions\2026\07').rglob('*.jsonl')):
    if p not in paths and p.stat().st_size > 1_000_000:
        paths.append(p)

for path in paths:
    if not path.exists():
        continue
    print('='*80)
    print('FILE', path.name, 'size', path.stat().st_size, 'mtime', path.stat().st_mtime)
    settings = []
    models = []
    grok_hits = []
    line_no = 0
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line_no += 1
            low = line.lower()
            interesting = (
                'thread_settings_applied' in line or
                '"model"' in line or
                'model_provider' in line or
                'grok' in low or
                'xai' in low
            )
            if not interesting:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                if 'grok' in low or 'xai' in low:
                    grok_hits.append((None, line_no, line[:200]))
                continue
            ts = obj.get('timestamp')
            typ = obj.get('type')
            payload = obj.get('payload') or {}
            if typ == 'event_msg' and isinstance(payload, dict) and payload.get('type') == 'thread_settings_applied':
                ts_set = payload.get('thread_settings') or {}
                settings.append((ts, ts_set.get('model'), ts_set.get('model_provider_id'), line_no))
            if isinstance(payload, dict):
                for k in ('model','model_name','active_model'):
                    if payload.get(k):
                        models.append((ts, f'{typ}.{k}', str(payload.get(k)), line_no))
                tc = payload.get('thread_settings') or {}
                if isinstance(tc, dict) and tc.get('model'):
                    models.append((ts, f'{typ}.thread_settings.model', str(tc.get('model')), line_no))
            if 'grok' in low or 'xai' in low:
                grok_hits.append((ts, line_no, line[:240]))

    print('settings_applied', len(settings))
    prev = None
    print('--- model transitions ---')
    for ts, model, provider, ln in settings:
        key = (model, provider)
        if key != prev:
            print(f'{ts} L{ln} model={model} provider={provider}')
            prev = key
    print('--- unique model strings ---')
    c = Counter([m for *_, m, __ in [(a,b,c,d) for a,b,c,d in [(t,k,m,l) for t,k,m,l in models]]])
    # fix
    c = Counter([m for _,_,m,_ in models])
    for k,v in c.most_common(40):
        print(f'{v:5d} {k}')
    print('--- grok/xai hits', len(grok_hits), '---')
    for ts, ln, snip in grok_hits[:40]:
        print(ts, f'L{ln}', snip.replace('\n',' ')[:220])
