"""Card edits in the site's own format.

The site's edit mode keeps these same structures in the browser, so an edit made here
appears in its fields and on My edits as if it was typed there. This module mirrors
atlasEdits.mjs of the site; the interoperability test keeps the two identical.
"""
import json
import os
from pathlib import Path
import tempfile
import time

PROPOSAL_FORMAT = 'octane.class-contribution.v2'
SEPARATOR = '\x1f'
LOCK_SECONDS = 10


def path_key(*parts): return SEPARATOR.join(parts)
def field_key(path, language): return f'{path}{SEPARATOR}{language}'
def now(): return int(time.time()*1000)
def base36(value):
    digits, text = '0123456789abcdefghijklmnopqrstuvwxyz', ''
    while value: value, digit = divmod(value, 36); text = digits[digit] + text
    return text or '0'
def blank(value): return value is None or (not value.strip() if isinstance(value, str) else not value if isinstance(value, list) else False)
def same(left, right): return ('' if left is None else left) == ('' if right is None else right)
def empty_edits(): return {'version': 1, 'sender': {'nick': '', 'contact': '', 'role': 'human'}, 'cards': {}}


def as_text(value):
    if value is None: return ''
    if isinstance(value, bool): return str(value).lower()
    if isinstance(value, (str, int, float)): return str(value)
    if isinstance(value, list): return '\n'.join(as_text(item) for item in value)
    if isinstance(value, dict): return '\n'.join(f'{key}: {as_text(item)}' for key, item in value.items())
    return str(value)


def entry_for(edits, card):
    entry = edits['cards'].setdefault(card['name'], {'id': card.get('id'), 'name': card['name'], 'fields': {}, 'additions': {}, 'evidence': {}, 'evidenceTargets': {}, 'notes': [], 'removed': {}, 'meta': {}, 'touchedAt': 0})
    entry.setdefault('removed', {})
    entry['touchedAt'] = now()
    return entry


def evidence_owner(kind, identifier): return path_key(kind, identifier)
def evidence_empty(item): return not (item.get('reference') or '').strip() and not (item.get('method') or '').strip() and not (item.get('summary') or '').strip()


def addition_empty(addition, evidence=()):
    values = [*addition['values']['ru'].values(), *addition['values']['en'].values()]
    return all(blank(value) for value in values) and all(evidence_empty(item) for item in evidence)


def has_changes(entry):
    return bool(entry['fields']) or bool(entry.get('notes')) or bool(entry.get('removed')) \
        or any(not addition_empty(item, entry['evidence'].get(evidence_owner('new', item['id']), ())) for item in entry['additions'].values()) \
        or any(not owner.startswith(f'new{SEPARATOR}') and any(not evidence_empty(item) for item in rows) for owner, rows in entry['evidence'].items())


def drop_if_unused(edits, name):
    entry = edits['cards'].get(name)
    if entry and not has_changes(entry) and not entry['additions']: del edits['cards'][name]


def changed_entries(edits):
    return sorted((entry for entry in edits['cards'].values() if has_changes(entry)), key=lambda entry: entry['name'])


def set_field(edits, card, path, language, value, base='', target=None):
    head, *rest = path.split(SEPARATOR)
    if head == 'new':
        identifier, field = rest
        if blank(value) and identifier not in edits['cards'].get(card['name'], {}).get('additions', {}): return
        entry = entry_for(edits, card)
        addition = entry['additions'].setdefault(identifier, {'id': identifier, 'kind': identifier, 'values': {'ru': {}, 'en': {}}, 'shared': {}})
        addition['values'][language][field] = value
        return
    key = field_key(path, language)
    if same(value, base):
        if card['name'] in edits['cards']:
            edits['cards'][card['name']]['fields'].pop(key, None)
            drop_if_unused(edits, card['name'])
        return
    entry_for(edits, card)['fields'][key] = {'value': value, 'base': base, 'target': target or {}}


def add_record(edits, card, kind):
    entry = entry_for(edits, card)
    identifier = f'n{base36(now())}{len(entry["additions"])}'
    entry['additions'][identifier] = {'id': identifier, 'kind': kind, 'values': {'ru': {}, 'en': {}}, 'shared': {'codeKind': 'pseudocode'} if kind == 'example' else {}}
    return entry['additions'][identifier]


def remove_addition(edits, name, identifier):
    entry = edits['cards'].get(name)
    if not entry: return
    entry['additions'].pop(identifier, None)
    entry['evidence'].pop(evidence_owner('new', identifier), None)
    drop_if_unused(edits, name)


def remove_record(edits, card, record):
    entry = entry_for(edits, card)
    entry['removed'][record['key']] = {'kind': record['kind'], 'revision': record['revision'], 'name': record['name']}
    prefix = path_key('record', record['key']) + SEPARATOR
    for key in [key for key in entry['fields'] if key.startswith(prefix)]: del entry['fields'][key]


def restore_record(edits, name, key):
    entry = edits['cards'].get(name)
    if not entry: return
    entry['removed'].pop(key, None)
    drop_if_unused(edits, name)


def add_evidence(edits, card, owner, row, target=None):
    entry = entry_for(edits, card)
    rows = entry['evidence'].setdefault(owner, [])
    entry['evidenceTargets'][owner] = target or {}
    rows.append({'id': f'e{base36(now())}{len(rows)}', 'kind': row.get('kind', 'ghidra_decompile'), 'method': row.get('method', ''), 'reference': row.get('reference', ''), 'summary': row.get('summary', '')})
    return rows[-1]


def set_nested(target, dotted, value):
    *parents, last = dotted.split('.')
    for part in parents: target = target.setdefault(part, {})
    target[last] = value


def to_list(value):
    return value if isinstance(value, list) else [line.strip() for line in str(value).split('\n') if line.strip()]


def evidence_of(rows):
    return [{'kind': row['kind'], 'reference': row['reference'].strip(), 'summary': (row.get('summary') or '').strip() or row['reference'].strip()} for row in rows if (row.get('reference') or '').strip()]


def card_changes(entry, scope):
    included = lambda language: scope == 'all' or scope == language
    articles, records, documents, changes = {}, {}, {}, []
    for key, edit in entry['fields'].items():
        *parts, language = key.split(SEPARATOR)
        head, identifier, *rest = parts
        # One readable name covers both languages, so a card's language choice leaves it alone.
        if head == 'display':
            changes.append({'kind': 'display-name', 'language': language, 'baseName': edit['base'], 'name': edit['value']})
            continue
        if not included(language): continue
        target = edit.get('target') or {}
        value = to_list(edit['value']) if target.get('list') else edit['value']
        if head == 'article':
            article = articles.setdefault(language, {'kind': 'article', 'language': language, 'baseRevision': target.get('revision') or ''})
            article[identifier] = value
        elif head == 'purpose':
            changes.append({'kind': 'method-purpose', 'language': language, 'method': identifier, 'basePurpose': edit['base'], 'purpose': value})
        elif head == 'doc':
            document = documents.setdefault((identifier, language), {'kind': 'method-documentation', 'language': language, 'method': identifier, 'baseRevision': target.get('revision') or '', 'documentation': {}})
            set_nested(document['documentation'], rest[0], value)
        elif head == 'record':
            record = records.setdefault((identifier, language), {'kind': 'record', 'language': language, 'key': identifier, 'recordKind': target.get('kind'), 'baseRevision': target.get('revision'), 'name': '', 'content': {}})
            if rest[0] == 'name': record['name'] = value
            else: record['content'][rest[1]] = value
    changes[:0] = articles.values()
    changes.extend(documents.values())
    for owner, rows in entry['evidence'].items():
        kind, identifier = owner.split(SEPARATOR)
        items, target = evidence_of(rows), entry['evidenceTargets'].get(owner) or {}
        if not items or not included('ru'): continue
        if kind == 'record':
            record = records.setdefault((identifier, 'ru'), {'kind': 'record', 'language': 'ru', 'key': identifier, 'recordKind': target.get('kind'), 'baseRevision': target.get('revision'), 'name': '', 'content': {}})
            record['evidence'] = items
        elif kind == 'method':
            document = documents.get((identifier, 'ru'))
            if document: document['documentation']['evidence'] = items
            else: changes.append({'kind': 'method-documentation', 'language': 'ru', 'method': identifier, 'baseRevision': target.get('revision') or '', 'documentation': {'evidence': items}})
    changes.extend(records.values())
    for key, record in (entry.get('removed') or {}).items():
        changes.append({'kind': 'record-removal', 'language': 'ru', 'key': key, 'recordKind': record['kind'], 'baseRevision': record['revision']})
    changes.extend(note for note in entry.get('notes') or [] if included(note['language']))
    for addition in entry['additions'].values():
        rows = evidence_of(entry['evidence'].get(evidence_owner('new', addition['id']), []))
        first = True
        for language in ('ru', 'en'):
            content = dict(addition['values'][language])
            name = content.pop('name', '')
            text = {key: value for key, value in content.items() if not blank(value)}
            if not included(language) or (blank(name) and not text): continue
            title = str(name).strip() or (addition.get('defaultName') or {}).get(language, '')
            change = {'kind': 'record', 'language': language, 'localId': addition['id'], 'recordKind': addition['kind'], 'baseRevision': 0, 'name': title, 'content': {**text, **addition['shared']}}
            if first and rows: change['evidence'] = rows
            changes.append(change)
            first = False
    return changes


def build_proposal(entries, sender, sha256):
    cards = []
    for entry in entries:
        scope = (entry.get('meta') or {}).get('language') or 'all'
        changes = card_changes(entry, scope)
        if changes: cards.append({'className': entry['name'], 'language': scope, 'role': sender['role'], 'author': {'name': sender['nick'].strip(), 'contact': sender['contact'].strip()}, 'comment': ((entry.get('meta') or {}).get('comment') or '').strip(), 'changes': changes})
    return {'format': PROPOSAL_FORMAT, 'elfSha256': sha256, 'publicationConsent': True, 'cards': cards}


def flatten(value, prefix=''):
    """Nested documentation becomes the dotted fields the method drawer edits."""
    rows = []
    for key, item in value.items():
        name = f'{prefix}{key}'
        if isinstance(item, dict): rows.extend(flatten(item, f'{name}.'))
        else: rows.append((name, item))
    return rows


def import_evidence(entry, owner, items, target=None):
    rows = entry['evidence'].setdefault(owner, [])
    rows.extend({'id': f'i{index}{base36(now())}', 'method': '', **item} for index, item in enumerate(items))
    entry['evidenceTargets'][owner] = target or {}


def import_change(edits, card, entry, change):
    language = change['language']
    kind = change['kind']
    if kind == 'note': entry['notes'].append(change)
    elif kind == 'display-name': set_field(edits, card, path_key('display', 'name'), language, change['name'], change['baseName'])
    elif kind == 'record-removal': entry['removed'][change['key']] = {'kind': change['recordKind'], 'revision': change['baseRevision'], 'name': ''}
    elif kind == 'article':
        for key in ('summary', 'description'):
            if key in change: set_field(edits, card, path_key('article', key), language, change[key], '', {'revision': change['baseRevision']})
    elif kind == 'method-purpose': set_field(edits, card, path_key('purpose', change['method']), language, change['purpose'], change['basePurpose'])
    elif kind == 'method-documentation':
        document = dict(change['documentation'])
        evidence = document.pop('evidence', None)
        if evidence: import_evidence(entry, evidence_owner('method', change['method']), evidence, {'revision': change['baseRevision']})
        for key, value in flatten(document):
            target = {'revision': change['baseRevision'], **({'list': True} if isinstance(value, list) and all(isinstance(item, str) for item in value) else {})}
            set_field(edits, card, path_key('doc', change['method'], key), language, '\n'.join(value) if target.get('list') else value, None, target)
    elif change.get('localId'):
        identifier = change['localId']
        addition = entry['additions'].setdefault(identifier, {'id': identifier, 'kind': change['recordKind'], 'values': {'ru': {}, 'en': {}}, 'shared': {}})
        content = dict(change['content'])
        code_kind = content.pop('codeKind', None)
        addition['values'][language].update({'name': change['name'], **content})
        if code_kind: addition['shared']['codeKind'] = code_kind
        if change.get('evidence'): import_evidence(entry, evidence_owner('new', identifier), change['evidence'])
    else:
        target = {'kind': change['recordKind'], 'revision': change['baseRevision']}
        if change.get('name'): set_field(edits, card, path_key('record', change['key'], 'name'), language, change['name'], '', target)
        for key, value in change['content'].items(): set_field(edits, card, path_key('record', change['key'], 'content', key), language, value, None, target)
        if change.get('evidence'): import_evidence(entry, evidence_owner('record', change['key']), change['evidence'], target)


def import_proposal(edits, proposal, sha256):
    if proposal.get('format') != PROPOSAL_FORMAT or not isinstance(proposal.get('cards'), list): raise ValueError('Неизвестный формат файла правок.')
    if sha256 and proposal.get('elfSha256') != sha256: raise ValueError('Файл правок относится к другой версии библиотеки.')
    for item in proposal['cards']:
        card = {'id': None, 'name': item['className']}
        entry = entry_for(edits, card)
        entry['meta'] = {**entry['meta'], 'comment': item.get('comment') or '', 'language': item.get('language')}
        if not edits['sender']['nick']:
            edits['sender'] = {'nick': item.get('author', {}).get('name', ''), 'contact': item.get('author', {}).get('contact', ''), 'role': item.get('role', 'ai')}
        for change in item['changes']: import_change(edits, card, entry, change)


def describe(entry):
    """Every edit with its full text, in the form a reader of My edits sees it."""
    rows = []
    for key, edit in entry['fields'].items():
        *parts, language = key.split(SEPARATOR)
        head, identifier, *rest = parts
        rows.append({'type': head, 'target': identifier, 'field': rest[-1] if rest else identifier, 'language': language, 'value': edit['value'], 'published': edit.get('base')})
    for addition in entry['additions'].values():
        rows.append({'type': 'new', 'target': addition['id'], 'field': addition['kind'], 'values': addition['values'], 'shared': addition['shared']})
    rows.extend({'type': 'removed', 'target': key, 'field': record['kind'], 'name': record.get('name', '')} for key, record in (entry.get('removed') or {}).items())
    evidence = [{'owner': owner.replace(SEPARATOR, ':'), **row} for owner, items in entry['evidence'].items() for row in items]
    return {'edits': rows, 'evidence': evidence, 'notes': entry.get('notes') or [], 'comment': (entry.get('meta') or {}).get('comment', ''), 'language': (entry.get('meta') or {}).get('language') or 'all'}


class EditStore:
    """One small file. It is shared by every MCP session and by the browser bridge."""

    def __init__(self, path):
        self.path = Path(path)
        self.guard = self.path.with_suffix('.lock')

    def read(self):
        try: value = json.loads(self.path.read_text(encoding='utf-8'))
        except (FileNotFoundError, ValueError): value = {'revision': 0, 'edits': empty_edits()}
        return value

    def write(self, state):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, name = tempfile.mkstemp(dir=self.path.parent, prefix='.edits-')
        with os.fdopen(handle, 'w', encoding='utf-8') as file: json.dump(state, file, ensure_ascii=False)
        os.replace(name, self.path)

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + LOCK_SECONDS
        while True:
            try:
                os.close(os.open(self.guard, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                return self
            except FileExistsError:
                if time.monotonic() > deadline: self.guard.unlink(missing_ok=True); deadline = time.monotonic() + LOCK_SECONDS
                time.sleep(0.01)

    def __exit__(self, *_):
        self.guard.unlink(missing_ok=True)

    def change(self, action):
        with self:
            state = self.read()
            result = action(state['edits'])
            state['revision'] += 1
            self.write(state)
            return result

    def replace(self, base_revision, edits):
        """A browser's copy wins only if it was made from the current state."""
        with self:
            state = self.read()
            if base_revision != state['revision']: return False, state
            state = {'revision': state['revision'] + 1, 'edits': edits}
            self.write(state)
            return True, state
