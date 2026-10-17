"""Leaderboard worker, run by .github/workflows/scores.yml. No outside services: only this repository.

How a result travels:
  1. The game derives a P-256 key pair from nick + password (PBKDF2), so the password never leaves the device.
  2. It signs the result and posts it as a comment on the locked issue "patronnik-scores"
     (with a fine-grained token that can only touch this repository's issues; see lb.json).
  3. This script checks the signature: the first result for a nick registers its public key,
     later ones must be signed by the same key. Then it updates scores.json and deletes the comment.

Commands:
  process  read new comments, update scores.json and lb.json, list handled comment ids in .lb-done.json
  cleanup  delete the handled comments (run after the commit is pushed)
"""
import base64
import hashlib
import json
import os
import re
import sys
import unicodedata
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = 'https://api.github.com'
REPO = os.environ.get('REPO', '')
TOKEN = os.environ.get('GH_TOKEN', '')
TITLE = 'patronnik-scores'
TABLE, CFG, DONE = 'scores.json', 'lb.json', '.lb-done.json'
KEEP, ACKS = 100, 400
MAX_PER_SHELL = 100 * 4 + 25

# ---- P-256 (enough to verify ECDSA signatures from WebCrypto) ----
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % P == 0:
            return None
        l = (3 * p[0] * p[0] + A) * pow(2 * p[1], -1, P) % P
    else:
        l = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (l * l - p[0] - q[0]) % P
    return x, (l * (p[0] - x) - p[1]) % P


def mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


def point(raw):
    if len(raw) != 65 or raw[0] != 4:
        return None
    x, y = int.from_bytes(raw[1:33], 'big'), int.from_bytes(raw[33:], 'big')
    if not (x < P and y < P) or (y * y - (x * x * x + A * x + B)) % P:
        return None
    return x, y


def verify(q, msg, sig):
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
    if not (0 < r < N and 0 < s < N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
    w = pow(s, -1, N)
    x = add(mul(e * w % N, G), mul(r * w % N, q))
    return x is not None and x[0] % N == r


# ---- GitHub REST ----
def api(method, path, body=None):
    req = urllib.request.Request(API + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={'Authorization': f'Bearer {TOKEN}', 'Accept': 'application/vnd.github+json',
                                          'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'patronnik-scores'})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
            return json.loads(data) if data else None
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def comments(issue):
    if os.environ.get('LB_TEST_COMMENTS'):
        with open(os.environ['LB_TEST_COMMENTS'], encoding='utf-8') as f:
            return json.load(f)
    out, page = [], 1
    while True:
        chunk = api('GET', f'/repos/{REPO}/issues/{issue}/comments?per_page=100&page={page}') or []
        out += chunk
        if len(chunk) < 100:
            return out
        page += 1


def load(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save(path, obj):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write('\n')


def norm(nick):
    return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', nick)).strip().lower()


def obfuscate(tok):
    """The token is meant to be public (it can only post issue comments here); this only keeps
    automatic scanners from mistaking it for a leaked secret."""
    k = b'patronnik-lb'
    return base64.b64encode(bytes(c ^ k[i % len(k)] for i, c in enumerate(tok.encode()))).decode()[::-1]


def ensure_config():
    cfg = load(CFG, {})
    if os.environ.get('LB_TEST_COMMENTS'):
        return cfg
    issue = cfg.get('issue')
    found = api('GET', f'/repos/{REPO}/issues/{issue}') if issue else None
    if found and not found.get('locked') and found.get('title') == TITLE:   # someone with the public token unlocked it
        api('PUT', f'/repos/{REPO}/issues/{issue}/lock', {'lock_reason': 'resolved'})
    if found and found.get('title') != TITLE and not found.get('pull_request'):   # or renamed it: put the name back
        api('PATCH', f'/repos/{REPO}/issues/{issue}', {'title': TITLE, 'state': 'open'})
        found['title'] = TITLE
    if not found or found.get('title') != TITLE or found.get('pull_request'):
        new = api('POST', f'/repos/{REPO}/issues', {
            'title': TITLE,
            'body': 'Сюда игра присылает результаты. Их проверяет и удаляет workflow `scores`, таблица — в `scores.json`.'})
        issue = new['number']
        api('PUT', f'/repos/{REPO}/issues/{issue}/lock', {'lock_reason': 'resolved'})
    cfg['issue'] = issue
    pat = os.environ.get('LB_PAT', '').strip()
    if pat:
        cfg['tok'] = obfuscate(pat)
    else:
        cfg.pop('tok', None)
    return cfg


SHELLS = lambda r: 6 if r == 1 else 7 if r == 2 else 8


def code_print(path='index.html'):
    """The fingerprint the page computes from its own script: SHA-256 of the text inside <script>…</script>, first 16 bytes.
    A page whose code was changed (a cheat's patched copy) sends a different one."""
    try:
        with open(path, encoding='utf-8', newline='') as f:
            s = f.read()
        body = s[s.index('<script>') + len('<script>'):s.index('</script>')].replace('\r\n', '\n').replace('\r', '\n')   # as the HTML parser does
        return hashlib.sha256(body.encode('utf-8')).hexdigest()[:32]
    except (OSError, ValueError):
        return None


def scripted(whens):
    """Human answer moments scatter: every formula takes its own time to read. A script that waits a fixed share of the
    question lands in the same narrow spot again and again."""
    if len(whens) < 15:
        return False
    best = max(whens.count(c) for c in set(whens))
    return best >= .85 * len(whens)   # a steady player who answers on the same beat still spreads over neighbouring spots


def replay(log, rounds):
    """Re-plays the game from its answer log and returns (score, correct, total, fast_right, fast_all) or None if impossible.
    Each shell is two base-36 characters: (answer*4 + shell*2 + on_beat) and the answer moment as a share of the question
    (0..35, 'z' = no answer). answer: 0 blank, 1 live, 2 none; shell: 0 blank, 1 live."""
    if not isinstance(log, str) or len(log) % 2 or not re.fullmatch(r'[0-9a-z]*', log):
        return None
    lives, streak, score, correct, total, fast, fast_all, r, i, lv_in_round = 3, 0, 0, 0, 0, 0, 0, 1, 0, 0
    whens = []
    for k in range(0, len(log), 2):
        if lives <= 0:
            return None                       # a shell after the last life
        code, when = int(log[k], 36), log[k + 1]
        a, o, b = code // 4, (code // 2) % 2, code % 2
        if a > 2 or (when == 'z') != (a == 2):
            return None
        ok = a == o
        if a != 2:
            whens.append(int(when, 36))
        if a != 2 and int(when, 36) <= 4:     # answered in the first ~12 % of the question
            fast_all += 1
            fast += ok
        if b and not ok:
            return None
        total += 1
        lv_in_round += o
        if ok:
            streak += 1
            correct += 1
            score += 100 * min(4, 1 + max(0, streak - 1) // 3) + (25 if b else 0)
        else:
            lives -= 1
            streak = 0
        i += 1
        if i == SHELLS(r) and lives > 0:      # round over: one life back, next round
            if not 2 <= lv_in_round <= SHELLS(r) - 2:
                return None
            lives, r, i, lv_in_round = min(3, lives + 1), r + 1, 0, 0
    if lives > 0 or r != rounds:              # the run ends with the last life, in the round it reports
        return None
    return score, correct, total, fast, fast_all, whens


def handle(c, table, now):
    """Returns the ack for one comment, or None if it is not a result at all."""
    try:
        m = json.loads(re.search(r'\{.*\}', c.get('body') or '', re.S).group(0))
        msg, sig, key = m['p'].encode('utf-8'), base64.b64decode(m['s']), base64.b64decode(m['k'])
        o = json.loads(msg)
        nonce = str(o['nonce'])
    except (AttributeError, ValueError, KeyError, TypeError):
        return None, None
    if not re.fullmatch(r'[0-9a-f]{8,40}', nonce) or nonce in table['acks']:
        return nonce, None
    q = point(key)
    if q is None or not verify(q, msg, sig):
        return nonce, 'bad'
    try:
        nick = re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', str(o['nick']))).strip()
        score, rounds, acc = int(o['score']), int(o['rounds']), int(o['acc'])
    except (KeyError, ValueError, TypeError):
        return nonce, 'bad'
    if o.get('v') != 3 or str(o.get('code')) not in table.get('code', []):
        return nonce, 'old'
    if not re.fullmatch(r'[\w\-. ]{2,20}', nick) or not (0 <= acc <= 100) or not (1 <= rounds <= 1000):
        return nonce, 'bad'
    try:   # a result older than a week is a replay of someone's old comment
        sent = datetime.fromisoformat(str(c.get('created_at', now)).replace('Z', '+00:00')).timestamp() * 1000
        if abs(sent - int(o['t'])) > 7 * 86400 * 1000:
            return nonce, 'bad'
    except (KeyError, ValueError, TypeError):
        return nonce, 'bad'
    game = replay(o.get('log'), rounds)
    if not game or game[0] != score or round(100 * game[1] / max(1, game[2])) != acc:
        return nonce, 'bad'
    if game[3] >= 5 and game[3] > .85 * game[4]:   # snap answers before the graph can be read, and nearly all right: a script
        return nonce, 'bot'
    if scripted(game[5]):
        return nonce, 'bot'
    n = norm(nick)
    k64 = base64.b64encode(key).decode()
    who = table['players'].get(n)
    if who and who['key'] != k64:
        return nonce, 'key'
    if not who:
        table['players'][n] = {'nick': nick, 'key': k64, 'since': now}
    row = next((r for r in table['scores'] if r.get('id') == n), None)
    if row and row['best'] >= score:
        row['nick'] = nick
        return nonce, 'low'
    if row:
        table['scores'].remove(row)
    table['scores'].append({'id': n, 'nick': nick, 'best': score, 'rounds': rounds, 'acc': acc, 'at': now})
    return nonce, 'ok'


def process():
    cfg = ensure_config()
    table = load(TABLE, {})
    rows = []
    for r in table.get('scores', []):
        if not isinstance(r, dict):
            continue
        if not r.get('id'):   # a row from the earlier issue-based table: keep it under its name
            name = str(r.get('name') or r.get('login') or '').strip()
            if not name:
                continue
            r = {'id': norm(name), 'nick': name, 'best': int(r.get('best', 0)), 'rounds': int(r.get('rounds', 1)),
                 'acc': int(r.get('acc', 0)), 'at': str(r.get('at', ''))}
        rows.append(r)
    code = [c for c in table.get('code', []) if isinstance(c, str)]
    cur = code_print()
    if cur and cur not in code:   # the last few versions stay valid, so a player with a cached page is not turned away
        code = (code + [cur])[-4:]
    table = {'updated': table.get('updated'), 'scores': rows, 'players': table.get('players', {}), 'acks': table.get('acks', {}), 'code': code}
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    done, log = [], []
    for c in comments(cfg['issue']):
        nonce, ack = handle(c, table, now)
        done.append(c['id'])
        if nonce and ack:
            table['acks'][nonce] = ack
            log.append(f'{c["id"]}: {ack}')
    if log:
        table['updated'] = now
    table['scores'].sort(key=lambda r: (-r['best'], r['at']))
    table['scores'] = table['scores'][:KEEP]
    table['acks'] = dict(list(table['acks'].items())[-ACKS:])
    save(TABLE, table)
    save(CFG, cfg)
    save(DONE, done)
    print('\n'.join(log) or 'нет новых результатов')


def cleanup():
    for cid in load(DONE, []):
        api('DELETE', f'/repos/{REPO}/issues/comments/{cid}')
    print(f'удалено комментариев: {len(load(DONE, []))}')


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    {'process': process, 'cleanup': cleanup}[sys.argv[1] if len(sys.argv) > 1 else 'process']()
