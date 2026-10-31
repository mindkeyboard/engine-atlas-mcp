"""Everything the tools do: reading the site, decompiling, and working with edits."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from . import edits as E
from .bridge import PORT

RECORD_KINDS = ('usage', 'property', 'field', 'static', 'global', 'constant', 'enum', 'flag', 'relation', 'example')
RECORD_FIELDS = {'summary', 'valueType', 'getter', 'setter', 'backingFields', 'units', 'coordinates', 'range', 'defaultValue', 'mutation', 'ownership',
                 'invalidation', 'targetClass', 'relationType', 'acquisition', 'lifetime', 'thread', 'limitations', 'code', 'verification'}
METHOD_FIELDS = {'summary', 'behavior', 'parameters', 'returns', 'instance_acquisition', 'thread', 'ownership', 'invalidation',
                 'preconditions', 'postconditions', 'side_effects', 'repeatability', 'example'}
EVIDENCE_KINDS = ('ghidra_decompile', 'ghidra_disassembly', 'ghidra_function_metadata', 'device_observation', 'resource_asset', 'research_reference')
NOTE_KINDS = ('observation', 'question', 'hypothesis', 'result')
LANGUAGES = ('ru', 'en')
GUIDE = Path(__file__).resolve().parent/'research-guide-ru.md'
UNKNOWN_PURPOSES = ('', 'unknown', None)


def language_of(value):
    if value not in LANGUAGES: raise ValueError('Язык: ru или en.')
    return value


def localized_publication(publication, language):
    if not publication: return None
    translated = (publication.get('localizations') or {}).get(language)
    if translated: return translated
    return publication if language == 'ru' and not publication.get('canonicalMissing') else None


def localized_method(method, language):
    if language == 'ru': return {'purpose': method.get('purpose') or '', 'documentation': method.get('documentation') or {}}
    translation = (method.get('localizations') or {}).get(language) or {}
    return {'purpose': translation.get('purpose') or '', 'documentation': translation.get('documentation') or {}}


def localized_record(record, language):
    if language == 'ru': return {'name': record['name'], 'content': record['content']}
    translation = (record.get('localizations') or {}).get(language) or {}
    return {'name': translation.get('name') or '', 'content': translation.get('content') or {}}


def read_nested(document, dotted):
    for part in dotted.split('.'):
        document = document.get(part) if isinstance(document, dict) else None
    return document


def short_name(method):
    return method['name'].split('(')[0].split('::')[-1]


def address_of(value):
    if isinstance(value, int): return value
    text = str(value).strip().lower()
    if re.fullmatch(r'0x[0-9a-f]+', text): return int(text, 16)
    if re.fullmatch(r'[0-9]+', text): return int(text)
    return None


def post_form(url, fields):
    body = urlencode(fields).encode()
    request = Request(url, data=body, headers={'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'engine-atlas-mcp'})
    with urlopen(request, timeout=60) as response: return response.status, response.url


class Atlas:
    def __init__(self, site, store, ghidra, bridge=None, data=None):
        self.site, self.store, self.ghidra, self.bridge = site, store, ghidra, bridge or {}
        self.data = Path(data) if data else store.path.parent

    # Links and overview

    def class_url(self, name):
        return f'{self.site.url}/ru/reference/?view=class&name={quote(name, safe="")}'

    @property
    def edits_url(self):
        return f'{self.site.url}/ru/reference/?view=edits&mcp=1'

    def pending(self):
        return self.store.read()['edits']

    def ghidra_state(self):
        try:
            info, problems = self.ghidra.check(self.site.program['imageBase'])
            return {'ready': not problems, 'url': self.ghidra.url, 'program': info['name'], 'problems': problems}
        except Exception as error:
            return {'ready': False, 'url': self.ghidra.url, 'problems': [str(error)]}

    def status(self):
        manifest = self.site.manifest()
        edits = E.changed_entries(self.pending())
        return {'site': self.site.url, 'datasetId': manifest.get('datasetId'), 'program': manifest['program'], 'counts': manifest['counts'], 'ghidra': self.ghidra_state(),
                'edits': {'classes': len(edits), 'file': str(self.store.path), 'openOnSite': self.edits_url, 'bridgePort': PORT, 'bridgeListening': bool(self.bridge.get('listening'))},
                'reminder': 'Правки появляются на сайте в режиме редактора и в «Моих правках» после открытия ссылки openOnSite. Публикует их только рассмотрение.'}

    # Reading

    def row(self, item):
        return {'id': item['id'], 'name': item['name'], 'displayNames': item.get('displayNames') or {}, 'namespace': item.get('namespace'), 'studied': item.get('studied'),
                'publicationStatus': item.get('publicationStatus'), 'category': (item.get('classification') or {}).get('category'), 'descendants': item.get('descendants')}

    def card_of(self, target):
        return self.site.card(self.site.resolve_class(target))

    def method_row(self, method, language, program):
        text = localized_method(method, language)
        return {'name': method['name'], 'address': f'0x{method["address"]:08X}', 'ghidraAddress': f'0x{method["address"] + program["imageBase"]:08X}', 'signature': method.get('signature'),
                'purpose': text['purpose'], 'maturity': method.get('maturity'), 'declaringClass': method.get('declaringClass'), 'documented': bool(text['documentation'])}

    def overlay(self, name):
        entry = self.pending()['cards'].get(name)
        return E.describe(entry) if entry and E.has_changes(entry) else None

    def get_class(self, target, language='ru', include_methods=True, include_research=True):
        language_of(language)
        card = self.card_of(target)
        program = self.site.program
        article = localized_publication(card.get('publication'), language) or {}
        result = {'id': card['id'], 'name': card['name'], 'url': self.class_url(card['name']), 'displayNames': card.get('displayNames') or {}, 'namespace': card.get('namespace'), 'subsystem': card.get('subsystem'),
                  'studied': card.get('studied'), 'status': (card.get('publication') or {}).get('status'), 'contributors': card.get('contributors') or [],
                  'article': {'language': language, 'summary': article.get('summary') or '', 'description': article.get('description') or '', 'missing': not article},
                  'bases': [item['name'] for item in card['bases']], 'derived': [item['name'] for item in card['derived']], 'ancestors': [item['name'] for item in card['ancestors']]}
        if include_methods:
            result['methods'] = [self.method_row(method, language, program) for method in card['methods']]
            result['inheritedMethodCount'] = len(card['inheritedMethods'])
        if include_research: result['research'] = self.research_view(card, language, False)
        pending = self.overlay(card['name'])
        if pending: result['pendingEdits'] = pending
        return result

    def get_classes(self, targets, language='ru', include_methods=False):
        results = []
        for target in targets[:16]:
            try: results.append(self.get_class(target, language, include_methods, False))
            except Exception as error: results.append({'target': target, 'error': str(error)})
        return {'classes': results}

    def get_structure(self, target):
        card = self.card_of(target)
        return {'name': card['name'], 'bases': card['bases'], 'derived': card['derived'], 'ancestors': card['ancestors'], 'layouts': card['layouts'], 'fields': card['fields'],
                'inheritedFields': card.get('inheritedFields') or [], 'vtables': card['vtables'], 'executableBindings': card.get('executableBindings') or []}

    def list_classes(self, namespace=None, studied_only=False, query=None, include_service=False, limit=50, offset=0):
        items = self.site.classes()
        if namespace is not None: items = [item for item in items if item.get('namespace') == namespace]
        if studied_only: items = [item for item in items if item.get('studied')]
        if not include_service: items = [item for item in items if item.get('studyEligible', True)]
        if query: items = [item for item in items if query.lower() in item['name'].lower()]
        return {'total': len(items), 'offset': offset, 'classes': [self.row(item) for item in items[offset:offset + limit]]}

    def list_namespaces(self, query=None, limit=100):
        items = [item for item in self.site.namespaces() if not query or query.lower() in str(item.get('name')).lower()]
        return {'total': len(items), 'namespaces': [{'name': item.get('name'), 'parent': item.get('parent'), 'classes': item.get('totalClasses'), 'studied': item.get('studiedClasses')} for item in items[:limit]]}

    def frontier(self, limit=20, namespace=None):
        items = [item for item in self.site.classes() if item.get('studyEligible') and not item.get('studied') and (namespace is None or item.get('namespace') == namespace)]
        items.sort(key=lambda item: (-(item.get('descendants') or 0), item['name']))
        return {'total': len(items), 'classes': [self.row(item) for item in items[:limit]]}

    def owner_of(self, name):
        """A method's class is its name without the last segment, when such a class exists."""
        scope = name.split('(')[0].rsplit('::', 1)[0] if '::' in name else ''
        known = {item['name']: item for item in self.site.classes()}
        while scope:
            if scope in known: return known[scope]
            scope = scope.rsplit('::', 1)[0] if '::' in scope else ''
        return None

    def free_function(self, selector):
        address = address_of(selector)
        base = self.site.program['imageBase']
        for namespace in self.site.function_namespaces():
            for function in self.site.free_functions(namespace):
                if function['name'] == selector or (address is not None and address in (function['address'], function['address'] + base)): return function
        return None

    def find_method(self, card, selector):
        methods = [*card['methods'], *card['inheritedMethods']]
        address = address_of(selector)
        base = self.site.program['imageBase']
        if address is not None: found = [method for method in methods if address in (method['address'], method['address'] + base)]
        else:
            text = str(selector).strip()
            found = [method for method in methods if method['name'] == text]
            found = found or [method for method in methods if method['name'].split('(')[0] == text.split('(')[0] and '(' not in text]
            found = found or [method for method in methods if short_name(method) == text.split('(')[0].split('::')[-1]]
            own = [method for method in found if method.get('declaringClass') in (None, card['name'])]
            if own and len(found) > 1: found = own
        if len(found) == 1: return found[0]
        if found: raise ValueError(f'Неоднозначный метод {selector}: {"; ".join(method["name"] for method in found[:10])}')
        raise ValueError(f'В {card["name"]} нет метода {selector}. Список даёт atlas_get_class_methods.')

    def locate(self, target=None, method=None):
        """Class card and method from whatever the model has: a class, a full name or an address."""
        selector = method if method is not None else target
        if target is not None and method is not None: return self.card_of(target), None
        address = address_of(selector)
        name = str(selector)
        if address is not None:
            function = self.ghidra.function_at(address if address >= self.site.program['imageBase'] else address + self.site.program['imageBase'])
            name = re.search(r'[\w:~<>]+::[\w~]+', json.dumps(function, ensure_ascii=False))
            name = name.group(0) if name else ''
        item = self.owner_of(name)
        if not item: raise ValueError(f'Не найден класс для {selector}. Передай target с именем класса.')
        return self.site.card(item), None

    def method_of(self, target=None, method=None):
        card, _ = self.locate(target, method)
        found = self.find_method(card, method if method is not None else target)
        declaring = found.get('declaringClass')
        if declaring and declaring != card['name']:
            # An inherited method's text belongs to the class that declares it.
            card = self.card_of(declaring)
            found = self.find_method(card, found['name'])
        return card, found

    def get_method(self, target=None, method=None, language='ru'):
        language_of(language)
        try: card, found = self.method_of(target, method)
        except ValueError:
            function = self.free_function(method if method is not None else target)
            if function: return self.function_view(function, language)
            raise
        return {'class': card['name'], **self.function_view(found, language)}

    def function_view(self, function, language):
        text = localized_method(function, language)
        program = self.site.program
        return {**self.method_row(function, language, program), 'documentation': text['documentation'], 'notes': function.get('notes') or [],
                'calling': function.get('callingConvention'), 'role': function.get('role'), 'bindings': function.get('bindings') or [],
                'translationPresent': {code: bool(localized_method(function, code)['documentation'] or localized_method(function, code)['purpose']) for code in LANGUAGES}}

    def get_class_methods(self, target, language='ru', include_inherited=False, problems_only=False, query=None, limit=200, offset=0):
        card = self.card_of(target)
        program = self.site.program
        methods = [*card['methods'], *(card['inheritedMethods'] if include_inherited else [])]
        rows = [self.method_row(method, language, program) for method in methods]
        if problems_only: rows = [row for row in rows if row['purpose'] in UNKNOWN_PURPOSES or not row['documented']]
        if query: rows = [row for row in rows if query.lower() in row['name'].lower() or query.lower() in row['purpose'].lower()]
        return {'class': card['name'], 'total': len(rows), 'offset': offset, 'methods': rows[offset:offset + limit]}

    def research_view(self, card, language, include_inherited):
        research = card.get('research') or {}
        records = [record for record in research.get('records') or [] if include_inherited or not record.get('inherited')]
        return {'coverage': research.get('coverage') or {},
                'notes': [note for note in research.get('notes') or [] if language in (None, 'all') or note.get('language', 'ru') == language],
                'records': [{'key': record['key'], 'kind': record['kind'], 'confirmation': record.get('confirmation'), 'revision': record.get('revision'), 'declaringClass': record.get('declaringClass'),
                             'evidence': record.get('evidence') or [], **localized_record(record, language or 'ru')} for record in records]}

    def get_class_research(self, target, language='ru', include_inherited=False):
        card = self.card_of(target)
        return {'class': card['name'], **self.research_view(card, language, include_inherited), 'pendingEdits': self.overlay(card['name'])}

    def get_research_notes(self, target, language=None):
        card = self.card_of(target)
        pending = self.overlay(card['name']) or {}
        return {'class': card['name'], 'published': self.research_view(card, language, False)['notes'], 'pending': pending.get('notes', [])}

    def search(self, query, kinds=None, language=None, in_text=False, limit=30):
        """Names everywhere; published text only in studied classes, the only ones that have it."""
        kinds = kinds or ['class', 'function']
        lowered = query.lower()
        results = []
        if 'class' in kinds:
            for item in self.site.classes():
                names = [item['name'], *(item.get('displayNames') or {}).values()]
                if any(lowered in name.lower() for name in names): results.append({'kind': 'class', **self.row(item)})
        if 'function' in kinds:
            for namespace in self.site.function_namespaces():
                results.extend({'kind': 'function', 'name': function['name'], 'address': f'0x{function["address"]:08X}'} for function in self.site.free_functions(namespace) if lowered in function['name'].lower())
        owner = self.owner_of(query) if '::' in query else None
        if owner:
            card = self.site.card(owner)
            results.extend({'kind': 'method', 'class': card['name'], 'name': method['name']} for method in card['methods'] if lowered in method['name'].lower())
        if in_text:
            studied = [item for item in self.site.classes() if item.get('studied')]
            for card in self.site.cards(studied): results.extend(self.text_hits(card, lowered, language))
        return {'total': len(results), 'results': results[:limit]}

    def text_hits(self, card, query, language):
        hits = []
        def scan(kind, label, code, text):
            if isinstance(text, str) and query in text.lower():
                position = text.lower().index(query)
                hits.append({'kind': kind, 'class': card['name'], 'name': label, 'language': code, 'excerpt': text[max(0, position - 60):position + 100]})
        for code in ([language] if language in LANGUAGES else LANGUAGES):
            article = localized_publication(card.get('publication'), code) or {}
            scan('article', 'summary', code, article.get('summary'))
            scan('article', 'description', code, article.get('description'))
            for method in card['methods']:
                scan('method', method['name'], code, localized_method(method, code)['purpose'])
                scan('method', method['name'], code, E.as_text(localized_method(method, code)['documentation']))
            for record in (card.get('research') or {}).get('records') or []:
                if record.get('inherited'): continue
                text = localized_record(record, code)
                scan('record', record['name'], code, text['name'])
                scan('record', record['name'], code, E.as_text(text['content']))
        return hits

    def research_tasks(self, target=None, namespace=None, include_details=False, limit=30, offset=0):
        if target is None:
            found = self.frontier(limit + offset, namespace)
            return {'namespace': namespace, 'total': found['total'], 'classes': found['classes'][offset:]}
        card = self.card_of(target)
        name = card['name']
        pending = self.pending()['cards'].get(name, {'fields': {}})
        def edited(path, language): return E.field_key(path, language) in pending['fields']
        tasks = []
        def add(kind, what, tool, arguments): tasks.append({'task': kind, 'what': what, 'writeTool': tool, 'writeArguments': arguments})
        for language in LANGUAGES:
            article = localized_publication(card.get('publication'), language) or {}
            for key, field in (('summary', 'short_summary'), ('description', 'developer_description')):
                if not (article.get(key) or '').strip() and not edited(E.path_key('article', key), language):
                    add('article', f'Нет {key} на {language}', 'atlas_set_class_documentation', {'target': name, 'language': language, field: '…'})
        for method in card['methods']:
            ru = localized_method(method, 'ru')
            if ru['purpose'] in UNKNOWN_PURPOSES and not edited(E.path_key('purpose', method['name']), 'ru'):
                add('purpose', f'Нет назначения: {method["name"]}', 'atlas_set_method_purpose', {'target': name, 'method': method['name'], 'purpose': '…'})
            if include_details:
                if not ru['documentation']: add('documentation', f'Нет подробностей: {method["name"]}', 'atlas_set_method_documentation', {'target': name, 'method': method['name'], 'documentation': {'behavior': {'description': '…'}}})
                if ru['purpose'] and not localized_method(method, 'en')['purpose']: add('translation', f'Нет перевода назначения: {method["name"]}', 'atlas_set_method_purpose', {'target': name, 'method': method['name'], 'purpose': '…', 'language': 'en'})
        return {'class': name, 'url': self.class_url(name), 'total': len(tasks), 'offset': offset, 'tasks': tasks[offset:offset + limit], 'pendingEdits': self.overlay(name) is not None}

    def guide(self):
        text = GUIDE.read_text(encoding='utf-8')
        return {'revision': hashlib.sha256(text.encode()).hexdigest()[:16], 'guide': text}

    def checklist(self, include_details=False):
        result = {'route': ['atlas_status', 'atlas_get_research_guide', 'atlas_get_research_tasks', 'atlas_get_class', 'atlas_get_method_context', 'запись правок', 'atlas_validate_edits', 'проверка критиком', 'atlas_send_edits или страница «Мои правки»'],
                  'recordKinds': RECORD_KINDS, 'noteKinds': NOTE_KINDS, 'evidenceKinds': EVIDENCE_KINDS}
        if include_details: result.update(recordFields=sorted(RECORD_FIELDS), methodFields=sorted(METHOD_FIELDS))
        return result

    # Decompilation

    def body(self, method, limit):
        address = method['address'] + self.site.program['imageBase']
        body = self.ghidra.decompile(address)
        return {'body': body[:limit], 'truncated': len(body) > limit, 'characters': len(body)}

    def method_context(self, target=None, method=None, language='ru', include_body=True, max_body_chars=8000):
        view = self.get_method(target, method, language)
        address = int(view['ghidraAddress'], 16)
        result = {**view, 'callers': self.ghidra.callers(address), 'callees': self.ghidra.callees(address)}
        if include_body:
            body = self.ghidra.decompile(address)
            result.update(body=body[:max_body_chars], bodyTruncated=len(body) > max_body_chars)
        return result

    def many(self, methods, action):
        def run(item):
            arguments = item if isinstance(item, dict) else {'method': item}
            try: return action(**arguments)
            except Exception as error: return {'method': item, 'error': str(error)}
        with ThreadPoolExecutor(4) as pool: return list(pool.map(run, methods[:32]))

    def method_contexts(self, methods, target=None, language='ru', include_body=True, max_body_chars=8000):
        return {'methods': self.many(methods, lambda method, target=target: self.method_context(target, method, language, include_body, max_body_chars))}

    def method_bodies(self, methods, target=None, max_body_chars=8000):
        def one(method, target=target):
            card, found = self.method_of(target, method)
            return {'class': card['name'], 'name': found['name'], **self.body(found, max_body_chars)}
        return {'methods': self.many(methods, one)}

    # Edits: each one lands where the site's edit mode keeps its own

    def saved(self, card, **extra):
        return {'saved': True, 'class': card['name'], 'url': self.class_url(card['name']), **extra}

    def ref(self, card):
        return {'id': card['id'], 'name': card['name']}

    def set_class_documentation(self, target, language='ru', short_summary=None, developer_description=None):
        language_of(language)
        if short_summary is None and developer_description is None: raise ValueError('Нужен short_summary или developer_description.')
        if short_summary is not None and len(short_summary) > 240: raise ValueError('short_summary длиннее 240 знаков.')
        card = self.card_of(target)
        article = localized_publication(card.get('publication'), language) or {}
        target_revision = {'revision': article.get('hash') or ''}
        def change(edits):
            for key, value in (('summary', short_summary), ('description', developer_description)):
                if value is not None: E.set_field(edits, self.ref(card), E.path_key('article', key), language, value, article.get(key) or '', target_revision)
        self.store.change(change)
        return self.saved(card)

    def set_display_name(self, target, name):
        """An awkward C++ name made readable; the same for both languages, never a translation."""
        if re.search('[\u0400-\u04FF]', name): raise ValueError('Читаемое имя пишется латиницей: это не перевод на русский.')
        if len(name) > 120: raise ValueError('Читаемое имя длиннее 120 знаков.')
        card = self.card_of(target)
        names = card.get('displayNames') or {}
        self.store.change(lambda edits: E.set_field(edits, self.ref(card), E.path_key('display', 'name'), 'ru', name, names.get('ru') or names.get('en') or '', {}))
        return self.saved(card)

    def export_oed(self, target, path=None):
        card = self.card_of(target)
        oed = card.get('oed')
        if not oed: raise ValueError(f'Для {card["name"]} файла OED нет: класс не изучен, и подтверждённых привязок нет. Либо сайт ещё на старой сборке.')
        file = Path(path) if path else self.data/'exports'/oed['fileName']
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(oed['text'], encoding='utf-8')
        return {'class': card['name'], 'path': str(file), 'confirmed': oed['confirmed'], 'drafts': oed['drafts'], 'excluded': oed.get('excluded') or [], 'text': oed['text'],
                'reminder': 'Строки с «#» не работают, пока их факты не подтверждены.'}

    def apply_purpose(self, edits, card, method, purpose, language):
        if len(purpose) > 180: raise ValueError(f'Назначение {method["name"]} длиннее 180 знаков.')
        E.set_field(edits, self.ref(card), E.path_key('purpose', method['name']), language, purpose, localized_method(method, language)['purpose'], {})

    def set_method_purpose(self, purpose, target=None, method=None, language='ru'):
        language_of(language)
        card, found = self.method_of(target, method)
        self.store.change(lambda edits: self.apply_purpose(edits, card, found, purpose, language))
        return self.saved(card, method=found['name'])

    def set_method_purposes(self, target, items, language='ru'):
        language_of(language)
        pairs = [(*self.method_of(target, item['method']), item['purpose']) for item in items[:100]]
        def change(edits):
            for card, method, purpose in pairs: self.apply_purpose(edits, card, method, purpose, language)
        self.store.change(change)
        return {'saved': len(pairs), 'class': pairs[0][0]['name'] if pairs else None}

    def set_method_documentation(self, documentation, target=None, method=None, language='ru'):
        language_of(language)
        card, found = self.method_of(target, method)
        document = dict(documentation)
        evidence = document.pop('evidence', [])
        unknown = set(document) - METHOD_FIELDS
        if unknown: raise ValueError(f'Неизвестные поля: {", ".join(sorted(unknown))}. Допустимы: {", ".join(sorted(METHOD_FIELDS))}.')
        if evidence and language != 'ru': raise ValueError('Основания общие и записываются с language=ru.')
        published = localized_method(found, language)['documentation']
        revision = found.get('documentationSha256') or '' if language == 'ru' else ((found.get('localizations') or {}).get('en') or {}).get('documentationSha256') or ''
        def change(edits):
            for key, value in E.flatten(document):
                path = E.path_key('doc', found['name'], key)
                if key == 'parameters': E.set_field(edits, self.ref(card), path, language, value, None, {'revision': revision})
                elif isinstance(value, list): E.set_field(edits, self.ref(card), path, language, '\n'.join(E.as_text(item) for item in value), E.as_text(read_nested(published, key)), {'revision': revision, 'list': True})
                else: E.set_field(edits, self.ref(card), path, language, value, E.as_text(read_nested(published, key)), {'revision': revision})
            for row in evidence:
                E.add_evidence(edits, self.ref(card), E.evidence_owner('method', found['name']), self.evidence_row(row, found), {'revision': found.get('documentationSha256') or ''})
        self.store.change(change)
        return self.saved(card, method=found['name'])

    def evidence_row(self, row, method=None):
        if row.get('kind', 'ghidra_decompile') not in EVIDENCE_KINDS: raise ValueError(f'Вид основания: {", ".join(EVIDENCE_KINDS)}.')
        result = dict(row)
        if method:
            result.setdefault('method', method['name'])
            program = self.site.program
            result.setdefault('reference', f'libasphalt8.so @ RVA 0x{method["address"]:08X} ({method["name"]}), SHA-256 {program["sha256"][:12]}')
        return result

    def find_record(self, card, key):
        for record in (card.get('research') or {}).get('records') or []:
            if record['key'] == key: return record
        return None

    def save_record(self, edits, card, kind=None, name=None, content=None, language='ru', record_key=None, evidence=None, confirmation=None, code_kind=None):
        language_of(language)
        content = dict(content or {})
        code_kind = content.pop('codeKind', code_kind)
        unknown = set(content) - RECORD_FIELDS
        if unknown: raise ValueError(f'Неизвестные поля записи: {", ".join(sorted(unknown))}.')
        record = self.find_record(card, record_key) if record_key else None
        if record_key and not record and record_key not in edits['cards'].get(card['name'], {}).get('additions', {}): raise ValueError(f'Нет записи {record_key} в {card["name"]}.')
        if record and record.get('inherited'): raise ValueError(f'Запись {record_key} унаследована: правь её в {record.get("declaringClass")}.')
        if confirmation == 'rejected':
            if not record: raise ValueError('Удалить можно только опубликованную запись.')
            E.remove_record(edits, self.ref(card), record)
            return record_key
        if not record and not record_key and kind == 'usage':
            usage = [item for item in (card.get('research') or {}).get('records') or [] if item['kind'] == 'usage' and not item.get('inherited') and item.get('confirmation') != 'rejected']
            record = usage[0] if usage else None
        if record:
            binding = {'kind': record['kind'], 'revision': record['revision'], 'name': record['name']}
            text = localized_record(record, language)
            if name is not None: E.set_field(edits, self.ref(card), E.path_key('record', record['key'], 'name'), language, name, text['name'], binding)
            for key, value in content.items():
                published = record['content'].get(key)
                listed = isinstance(published, list)
                E.set_field(edits, self.ref(card), E.path_key('record', record['key'], 'content', key), language, '\n'.join(map(E.as_text, value)) if isinstance(value, list) else value, E.as_text(text['content'].get(key)), {**binding, **({'list': True} if listed or isinstance(value, list) else {})})
            for row in evidence or []: E.add_evidence(edits, self.ref(card), E.evidence_owner('record', record['key']), self.evidence_row(row), {'kind': record['kind'], 'revision': record['revision']})
            return record['key']
        if kind not in RECORD_KINDS and not record_key: raise ValueError(f'Вид записи: {", ".join(RECORD_KINDS)}.')
        entry = E.entry_for(edits, self.ref(card))
        if record_key: addition = entry['additions'][record_key]
        elif kind == 'usage':
            addition = entry['additions'].setdefault('usage', {'id': 'usage', 'kind': 'usage', 'values': {'ru': {}, 'en': {}}, 'shared': {}})
            addition['defaultName'] = {'ru': 'Работа с объектом', 'en': 'Working with the object'}
        else:
            if not name and not content.get('summary'): raise ValueError('Для новой записи нужно название или summary.')
            addition = E.add_record(edits, self.ref(card), kind)
        if name is not None: addition['values'][language]['name'] = name
        addition['values'][language].update(content)
        if code_kind: addition['shared']['codeKind'] = code_kind
        for row in evidence or []: E.add_evidence(edits, self.ref(card), E.evidence_owner('new', addition['id']), self.evidence_row(row))
        return addition['id']

    def save_reference_record(self, target, **arguments):
        card = self.card_of(target)
        key = self.store.change(lambda edits: self.save_record(edits, card, **arguments))
        return self.saved(card, record_key=key)

    def save_reference_records(self, items):
        cards = [self.card_of(item['target']) for item in items[:200]]
        def change(edits):
            return [self.save_record(edits, card, **{key: value for key, value in item.items() if key != 'target'}) for card, item in zip(cards, items)]
        return {'saved': self.store.change(change)}

    def restore_reference_record(self, target, record_key):
        card = self.card_of(target)
        self.store.change(lambda edits: E.restore_record(edits, card['name'], record_key))
        return self.saved(card)

    def remove_new_record(self, target, record_key):
        card = self.card_of(target)
        self.store.change(lambda edits: E.remove_addition(edits, card['name'], record_key))
        return self.saved(card)

    def add_evidence(self, target, owner, identifier, reference=None, summary='', kind='ghidra_decompile'):
        card = self.card_of(target)
        if owner == 'method':
            card, method = self.method_of(target, identifier)
            row = self.evidence_row({'kind': kind, 'summary': summary, **({'reference': reference} if reference else {})}, method)
            identity, revision = method['name'], {'revision': method.get('documentationSha256') or ''}
        elif owner == 'record':
            record = self.find_record(card, identifier)
            if not record: raise ValueError(f'Нет записи {identifier}.')
            row, identity, revision = self.evidence_row({'kind': kind, 'reference': reference, 'summary': summary}), identifier, {'kind': record['kind'], 'revision': record['revision']}
        else: raise ValueError('owner: method или record.')
        if not row.get('reference'): raise ValueError('Нужен reference.')
        self.store.change(lambda edits: E.add_evidence(edits, self.ref(card), E.evidence_owner(owner, identity), row, revision))
        return self.saved(card)

    def save_note(self, target, text, kind='observation', language='ru'):
        language_of(language)
        if kind not in NOTE_KINDS: raise ValueError(f'Вид заметки: {", ".join(NOTE_KINDS)}.')
        card = self.card_of(target)
        self.store.change(lambda edits: E.entry_for(edits, self.ref(card))['notes'].append({'kind': 'note', 'language': language, 'noteKind': kind, 'text': text}))
        return self.saved(card)

    def set_sender(self, nick=None, contact=None, role=None):
        if role not in (None, 'ai', 'human'): raise ValueError('role: ai или human.')
        values = {'nick': nick, 'contact': contact, 'role': role}
        def change(edits):
            edits['sender'].update({key: value for key, value in values.items() if value is not None})
            return edits['sender']
        return {'sender': self.store.change(change)}

    def set_options(self, target, comment=None, language=None):
        if language not in (None, 'all', 'ru', 'en'): raise ValueError('language: all, ru или en.')
        card = self.card_of(target)
        def change(edits):
            entry = edits['cards'].get(card['name'])
            if not entry: raise ValueError(f'Правок для {card["name"]} нет.')
            if comment is not None: entry['meta']['comment'] = comment
            if language is not None: entry['meta']['language'] = language
            entry['touchedAt'] = E.now()
        self.store.change(change)
        return self.saved(card)

    def list_edits(self):
        edits = self.pending()
        cards = []
        for entry in E.changed_entries(edits):
            scope = (entry.get('meta') or {}).get('language') or 'all'
            changes = E.card_changes(entry, scope)
            counts = {}
            for change in changes: counts[change['kind']] = counts.get(change['kind'], 0) + 1
            cards.append({'class': entry['name'], 'url': self.class_url(entry['name']), 'changes': len(changes), 'kinds': counts, 'language': scope, 'comment': (entry.get('meta') or {}).get('comment', ''), 'editedAt': entry.get('touchedAt')})
        return {'sender': edits['sender'], 'total': len(cards), 'cards': cards, 'openOnSite': self.edits_url}

    def get_edits(self, target):
        name = self.site.resolve_class(target)['name']
        entry = self.pending()['cards'].get(name)
        if not entry: return {'class': name, 'edits': []}
        return {'class': name, 'url': self.class_url(name), **E.describe(entry)}

    def discard(self, classes=None, everything=False):
        if not classes and not everything: raise ValueError('Укажи classes или all=true.')
        def change(edits):
            names = list(edits['cards']) if everything else [self.site.resolve_class(item)['name'] for item in classes]
            for name in names: edits['cards'].pop(name, None)
            return names
        return {'discarded': self.store.change(change)}

    def selected(self, classes):
        edits = self.pending()
        entries = E.changed_entries(edits)
        if classes:
            names = {self.site.resolve_class(item)['name'] for item in classes}
            entries = [entry for entry in entries if entry['name'] in names]
        return edits, entries

    def proposal(self, classes=None):
        edits, entries = self.selected(classes)
        value = E.build_proposal(entries, edits['sender'], self.site.program['sha256'])
        if not value['cards']: raise ValueError('Правок нет.')
        return value

    def validate(self, classes=None):
        """Catches on this side what review would refuse, and edits that went stale."""
        edits, entries = self.selected(classes)
        problems = []
        for entry in entries:
            card = self.card_of(entry['name'])
            methods = {method['name']: method for method in [*card['methods'], *card['inheritedMethods']]}
            records = {record['key']: record for record in (card.get('research') or {}).get('records') or []}
            def report(where, text): problems.append({'class': entry['name'], 'where': where, 'problem': text})
            for change in E.card_changes(entry, (entry.get('meta') or {}).get('language') or 'all'):
                kind, language = change['kind'], change['language']
                if kind == 'display-name':
                    names = card.get('displayNames') or {}
                    if change['baseName'] != (names.get('ru') or names.get('en') or ''): report('display-name', 'Читаемое имя на сайте изменилось после начала правки.')
                elif kind == 'article':
                    current = (localized_publication(card.get('publication'), language) or {}).get('hash') or ''
                    if change['baseRevision'] != current: report('article', 'Статья на сайте изменилась после начала правки.')
                    if len(change.get('summary', '')) > 240: report('article', 'summary длиннее 240 знаков.')
                    if 'summary' in change and len(change['summary'].strip()) < 10: report('article', 'summary короче 10 знаков.')
                    if 'description' in change and len(change['description'].strip()) < 80: report('article', 'Описание короче 80 знаков.')
                elif kind in ('method-purpose', 'method-documentation'):
                    method = methods.get(change['method'])
                    if not method: report(change['method'], 'Такого метода в карточке нет.')
                    elif kind == 'method-purpose':
                        if len(change['purpose']) > 180: report(change['method'], 'Назначение длиннее 180 знаков.')
                        if change['basePurpose'] != localized_method(method, language)['purpose']: report(change['method'], 'Назначение на сайте изменилось после начала правки.')
                    elif language == 'ru' and change['baseRevision'] != (method.get('documentationSha256') or ''): report(change['method'], 'Описание метода на сайте изменилось после начала правки.')
                elif kind in ('record', 'record-removal') and 'key' in change:
                    record = records.get(change['key'])
                    if not record: report(change['key'], 'Такой записи в карточке нет.')
                    elif record['revision'] != change['baseRevision']: report(change['key'], 'Запись на сайте изменилась после начала правки.')
                elif kind == 'record' and not (change['name'].strip() or str(change['content'].get('summary', '')).strip()): report(change['localId'], 'У новой записи нет названия и смысла.')
        if not edits['sender']['nick'].strip(): problems.append({'class': None, 'where': 'sender', 'problem': 'Не указан ник: вызови atlas_set_sender с именем модели или человека.'})
        return {'valid': not problems, 'checkedClasses': len(entries), 'problems': problems}

    def export(self, classes=None, path=None):
        value = self.proposal(classes)
        target = Path(path) if path else self.data/'exports'/f'atlas-edits-{datetime.now():%Y%m%d-%H%M%S}.json'
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
        return {'path': str(target), 'classes': len(value['cards']), 'changes': sum(len(card['changes']) for card in value['cards'])}

    def import_file(self, path):
        value = json.loads(Path(path).read_text(encoding='utf-8-sig'))
        self.store.change(lambda edits: E.import_proposal(edits, value, self.site.program['sha256']))
        return {'imported': len(value['cards']), 'openOnSite': self.edits_url}

    def send(self, confirmed=False, classes=None):
        if not confirmed: raise ValueError('Отправка публикует правки на рассмотрение с указанным ником. Спроси пользователя и вызови снова с confirmed=true.')
        check = self.validate(classes)
        if not check['valid']: return {'sent': False, **check}
        contributions = self.site.publication().get('contributions') or {}
        form, entry = contributions.get('googleFormsUrl'), contributions.get('googleFormsJsonEntry')
        if not contributions.get('enabled') or not form or not entry: raise ValueError('На сайте не настроена отправка правок. Открой «Мои правки» и отправь оттуда.')
        parts = urlsplit(form)
        if parts.scheme != 'https' or parts.netloc != 'docs.google.com' or not parts.path.endswith('/viewform'): raise ValueError(f'Неподходящий адрес формы: {form}')
        value = self.proposal(classes)
        try: post_form(f'https://docs.google.com{parts.path[:-len("viewform")]}formResponse', {entry: json.dumps(value, ensure_ascii=False), 'fvv': '1', 'pageHistory': '0'})
        except (HTTPError, URLError, OSError) as error:
            raise ValueError(f'Форма не приняла отправку: {error}. Выгрузи файл через atlas_export_edits или отправь со страницы «Мои правки».') from error
        return {'sent': True, 'classes': len(value['cards'])}
