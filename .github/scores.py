"""Adds one result from a GitHub issue to scores.json. Run by .github/workflows/scores.yml.

The issue body carries a JSON block made by the game. The player is identified by the
GitHub account that opened the issue, so nobody can overwrite someone else's best score.
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

TABLE = 'scores.json'
KEEP = 100


def sig(o):
    s = f"{o['name']}|{o['score']}|{o['rounds']}|{o['acc']}|{o['session']}|patronnik-v2".encode('utf-8')
    h = 0x811c9dc5
    for b in s:
        h ^= b
        h = (h * 16777619) & 0xffffffff
    return f'{h:08x}'


def main():
    body = os.environ.get('BODY', '')
    login = os.environ.get('LOGIN', '')
    m = re.search(r'\{.*\}', body, re.S)
    if not m:
        return 'Не нашёл результат в заявке: в ней должен быть блок JSON, который делает игра.'
    try:
        o = json.loads(m.group(0))
        o = {'name': str(o['name'])[:24].strip() or login, 'score': int(o['score']), 'rounds': int(o['rounds']),
             'acc': int(o['acc']), 'session': str(o['session'])[:16], 'sig': str(o['sig'])}
    except (ValueError, KeyError, TypeError):
        return 'Результат в заявке повреждён.'
    if o['sig'] != sig(o) or not (0 <= o['score'] <= 10_000_000) or not (1 <= o['rounds'] <= 1000) or not (0 <= o['acc'] <= 100):
        return 'Результат не прошёл проверку. Отправьте его кнопкой из игры, не меняя текст заявки.'
    try:
        with open(TABLE, encoding='utf-8') as f:
            table = json.load(f)
    except (OSError, ValueError):
        table = {'scores': []}
    rows = [r for r in table.get('scores', []) if isinstance(r, dict)]
    mine = next((r for r in rows if r.get('login') == login), None)
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    if mine and mine.get('best', 0) >= o['score']:
        mine['name'] = o['name']
        msg = f"Ваш лучший результат {mine['best']} выше, таблица не изменилась (имя обновлено)."
    else:
        if mine:
            rows.remove(mine)
        rows.append({'login': login, 'name': o['name'], 'best': o['score'], 'rounds': o['rounds'], 'acc': o['acc'], 'at': now})
        msg = f"Записал {o['score']} очков ({o['name']})."
    rows.sort(key=lambda r: (-r.get('best', 0), r.get('at', '')))
    table = {'updated': now, 'scores': rows[:KEEP]}
    with open(TABLE, 'w', encoding='utf-8') as f:
        json.dump(table, f, ensure_ascii=False, indent=1)
        f.write('\n')
    return msg


if __name__ == '__main__':
    result = main()
    with open('result.txt', 'w', encoding='utf-8') as f:
        f.write(result)
    sys.stdout.reconfigure(encoding='utf-8')
    print(result)
