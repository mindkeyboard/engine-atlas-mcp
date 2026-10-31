"""The MCP against a small stand-in for the site: reading, edits, the browser link, sending."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from engine_atlas_mcp import atlas as atlas_module, bridge, edits as E, server
from engine_atlas_mcp.atlas import Atlas
from engine_atlas_mcp.edits import EditStore
from engine_atlas_mcp.ghidra import Ghidra, GhidraError
from engine_atlas_mcp.site import Site, SiteError

SHA = 'a'*64
METHOD = {'id': 7, 'declaringClass': 'gin::Widget', 'address': 0x2000, 'name': 'gin::Widget::Paint(int)', 'signature': 'void Paint(int)', 'purpose': 'Рисует виджет', 'documentationSha256': 'd'*64,
          'localizations': {}, 'documentation': {'summary': 'Рисует виджет', 'preconditions': ['Объект жив'], 'behavior': {'description': 'Текст'}}}
BARE = {'id': 8, 'declaringClass': 'gin::Widget', 'address': 0x2100, 'name': 'gin::Widget::Hide()', 'signature': None, 'purpose': 'unknown', 'localizations': {}, 'documentation': None}
RECORD = {'key': 'reference:1', 'kind': 'property', 'name': 'Ширина', 'revision': 3, 'content': {'summary': 'Ширина в пикселях', 'getter': ['gin::Widget::Width()']}, 'confirmation': 'confirmed', 'evidence': [], 'localizations': {'en': {'name': 'Width', 'content': {'summary': 'Width in pixels'}}}}
CARD = {'id': 1, 'name': 'gin::Widget', 'displayNames': {'ru': 'Виджет'}, 'namespace': {'name': 'gin'}, 'subsystem': 'ui', 'studied': True, 'contributors': [],
        'publication': {'status': 'PUBLIC', 'summary': 'Основа интерфейса', 'description': 'Базовый элемент экрана', 'hash': 'b'*64, 'localizations': {'en': {'summary': 'Interface base', 'description': 'Screen element', 'hash': 'c'*64}}},
        'bases': [], 'derived': [], 'ancestors': [], 'layouts': [], 'fields': [], 'vtables': [], 'methods': [METHOD, BARE], 'inheritedMethods': [], 'research': {'notes': [], 'records': [RECORD], 'coverage': {}},
        'oed': {'fileName': 'gin_Widget.oed', 'text': 'oed 2\nnamespace atlas.engine\n', 'confirmed': 1, 'drafts': 2, 'excluded': []}}
INDEX = {'id': 1, 'name': 'gin::Widget', 'displayNames': {'ru': 'Виджет'}, 'namespace': 'gin', 'studied': True, 'studyEligible': True, 'publicationStatus': 'PUBLIC', 'descendants': 2, 'shard': 'aa'}
FILES = {
    'atlas/manifest.json': {'datasetId': 'one', 'datasetBase': 'data/', 'views': {}, 'program': {'name': 'libasphalt8.so', 'sha256': SHA, 'imageBase': 0x10000}, 'counts': {'classes': 1, 'studiedClasses': 1}},
    'atlas/data/classes/index.json': {'classes': [INDEX]},
    'atlas/data/classes/aa.json': {'classes': {'1': CARD}},
    'atlas/data/namespaces.json': {'namespaces': [{'name': 'gin', 'parent': None, 'totalClasses': 1, 'studiedClasses': 1}]},
    'atlas/data/functions/index.json': {'namespaces': [{'name': 'global', 'count': 1, 'shard': 'ff'}]},
    'atlas/data/functions/ff.json': {'functions': [{'id': 9, 'address': 0x3000, 'name': 'ABundle_Clear', 'signature': None, 'purpose': 'unknown', 'localizations': {}}]},
    'publication.json': {'mode': 'both', 'contributions': {'enabled': True, 'googleFormsUrl': 'https://docs.google.com/forms/d/e/ID/viewform', 'googleFormsJsonEntry': 'entry.1'}},
}


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *_): pass


class FakeGhidra(Ghidra):
    def __init__(self): super().__init__('http://127.0.0.1:1')
    def get(self, path, timeout=60, **parameters):
        return {'/get_current_program_info': {'name': 'libasphalt8.so', 'image_base': '00010000'}, '/decompile_function': {'result': f'body {parameters.get("address")}'}, '/get_function_by_address': {'name': 'gin::Widget::Hide'}}.get(path, [])


class Base(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        site = self.root/'site'
        for path, value in FILES.items():
            (site/path).parent.mkdir(parents=True, exist_ok=True)
            (site/path).write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
        self.http = ThreadingHTTPServer(('127.0.0.1', 0), partial(Quiet, directory=str(site)))
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        self.url = f'http://127.0.0.1:{self.http.server_port}'
        self.store = EditStore(self.root/'data/edits.json')
        self.atlas = Atlas(Site(self.url), self.store, FakeGhidra())
        self.call = server.dispatch(self.atlas)


class ReadingTests(Base):
    def test_nothing_needs_a_local_database(self):
        names = {path.stem for path in Path(server.__file__).parent.glob('*.py')}
        self.assertNotIn('drafts', names)
        self.assertNotIn('sqlite', ' '.join(path.read_text(encoding='utf-8') for path in Path(server.__file__).parent.glob('*.py')))
        self.assertFalse((self.root/'data').exists())

    def test_default_site_is_the_public_one(self):
        self.assertEqual(Site().url, 'https://octane-loader.utmsoft.ru')

    def test_reads_in_each_language(self):
        self.assertEqual(self.call('atlas_get_class', {'target': 'gin::Widget'})['article']['summary'], 'Основа интерфейса')
        self.assertEqual(self.call('atlas_get_class', {'target': 'Виджет', 'language': 'en'})['article']['summary'], 'Interface base')

    def test_search_by_name_and_by_text_per_language(self):
        self.assertEqual(self.call('atlas_search', {'query': 'widget'})['results'][0]['name'], 'gin::Widget')
        self.assertEqual(self.call('atlas_search', {'query': 'Abundle'})['results'][0]['kind'], 'function')
        self.assertEqual(self.call('atlas_search', {'query': 'пикселях', 'in_text': True, 'language': 'ru', 'kinds': ['class']})['total'], 1)
        self.assertEqual(self.call('atlas_search', {'query': 'пикселях', 'in_text': True, 'language': 'en', 'kinds': ['class']})['total'], 0)

    def test_method_found_by_name_rva_and_ghidra_address(self):
        for selector in ('gin::Widget::Paint(int)', 'gin::Widget::Paint', '0x2000', 0x12000):
            found = self.call('atlas_get_method', {'target': 'gin::Widget', 'method': selector} if isinstance(selector, int) or selector.startswith('0x') else {'method': selector})
            self.assertEqual(found['name'], METHOD['name'], selector)
        self.assertEqual(found['ghidraAddress'], '0x00012000')

    def test_free_function_is_found_too(self):
        self.assertEqual(self.call('atlas_get_method', {'method': 'ABundle_Clear'})['name'], 'ABundle_Clear')

    def test_decompilation_uses_the_ghidra_address(self):
        self.assertIn('0x00012000', self.call('atlas_get_method_context', {'method': 'gin::Widget::Paint'})['body'])

    def test_tasks_name_the_gaps_and_how_to_fill_them(self):
        tasks = self.call('atlas_get_research_tasks', {'target': 'gin::Widget'})['tasks']
        self.assertEqual([task['writeTool'] for task in tasks], ['atlas_set_method_purpose'])
        self.call('atlas_set_method_purpose', {'method': 'gin::Widget::Hide', 'purpose': 'Прячет виджет'})
        self.assertEqual(self.call('atlas_get_research_tasks', {'target': 'gin::Widget'})['tasks'], [])

    def test_guide_describes_this_server(self):
        guide = self.call('atlas_get_research_guide', {})['guide']
        names = {item['name'] for item in server.tools()}
        import re
        self.assertLessEqual(set(re.findall(r'atlas_[a-z_]+', guide)), names)

    def test_old_build_is_reported_plainly(self):
        with self.assertRaises(SiteError): Site(self.url + '/missing').manifest()


class EditTests(Base):
    def proposal(self): return self.call('atlas_export_edits', {'path': str(self.root/'out.json')}) and json.loads((self.root/'out.json').read_text(encoding='utf-8'))

    def test_edits_use_the_paths_the_site_reads(self):
        self.call('atlas_set_class_documentation', {'target': 'gin::Widget', 'short_summary': 'Новое краткое описание', 'language': 'ru'})
        self.call('atlas_set_method_documentation', {'method': 'gin::Widget::Paint', 'documentation': {'behavior': {'description': 'Новый текст'}, 'preconditions': ['А', 'Б']}})
        fields = self.store.read()['edits']['cards']['gin::Widget']['fields']
        self.assertEqual(fields[E.field_key(E.path_key('article', 'summary'), 'ru')]['target'], {'revision': 'b'*64})
        document = fields[E.field_key(E.path_key('doc', METHOD['name'], 'behavior.description'), 'ru')]
        self.assertEqual((document['value'], document['base'], document['target']), ('Новый текст', 'Текст', {'revision': 'd'*64}))
        listed = fields[E.field_key(E.path_key('doc', METHOD['name'], 'preconditions'), 'ru')]
        self.assertEqual((listed['value'], listed['base'], listed['target']['list']), ('А\nБ', 'Объект жив', True))

    def test_unchanged_value_is_not_an_edit(self):
        self.call('atlas_set_class_documentation', {'target': 'gin::Widget', 'short_summary': 'Основа интерфейса'})
        self.assertEqual(self.call('atlas_list_edits', {})['total'], 0)

    def test_proposal_carries_everything_a_card_can_change(self):
        self.call('atlas_set_sender', {'nick': 'Sonnet 5.5', 'role': 'ai'})
        self.call('atlas_batch', {'requests': [
            {'tool': 'atlas_set_class_documentation', 'arguments': {'target': 'gin::Widget', 'language': 'en', 'short_summary': 'A better summary'}},
            {'tool': 'atlas_set_method_purpose', 'arguments': {'method': 'gin::Widget::Hide', 'purpose': 'Прячет виджет'}},
            {'tool': 'atlas_set_method_documentation', 'arguments': {'method': 'gin::Widget::Paint', 'documentation': {'summary': 'Рисует', 'evidence': [{'kind': 'ghidra_decompile', 'summary': 'Вызов'}]}}},
            {'tool': 'atlas_save_reference_record', 'arguments': {'target': 'gin::Widget', 'record_key': 'reference:1', 'name': 'Ширина элемента', 'content': {'getter': ['gin::Widget::GetWidth()']}}},
            {'tool': 'atlas_save_reference_record', 'arguments': {'target': 'gin::Widget', 'kind': 'example', 'name': 'Пример', 'content': {'summary': 'Смысл', 'code': 'x();', 'codeKind': 'cpp'}}},
            {'tool': 'atlas_save_research_note', 'arguments': {'target': 'gin::Widget', 'text': 'Вопрос', 'kind': 'question'}},
        ], 'stop_on_error': True})
        proposal = self.proposal()
        self.assertEqual(proposal['elfSha256'], SHA)
        card = proposal['cards'][0]
        self.assertEqual((card['role'], card['author']['name']), ('ai', 'Sonnet 5.5'))
        kinds = [change['kind'] for change in card['changes']]
        self.assertEqual(sorted(set(kinds)), ['article', 'method-documentation', 'method-purpose', 'note', 'record'])
        document = next(change for change in card['changes'] if change['kind'] == 'method-documentation')
        self.assertIn('RVA 0x00002000', document['documentation']['evidence'][0]['reference'])
        record = next(change for change in card['changes'] if change.get('key') == 'reference:1')
        self.assertEqual((record['baseRevision'], record['content']['getter']), (3, ['gin::Widget::GetWidth()']))
        new = next(change for change in card['changes'] if change.get('localId'))
        self.assertEqual(new['content'], {'summary': 'Смысл', 'code': 'x();', 'codeKind': 'cpp'})

    def test_readable_name_is_one_field_and_never_a_translation(self):
        with self.assertRaises(ValueError): self.call('atlas_set_class_display_name', {'target': 'gin::Widget', 'name': 'Виджет интерфейса'})
        self.call('atlas_set_class_display_name', {'target': 'gin::Widget', 'name': 'Screen Element'})
        self.call('atlas_set_edit_options', {'target': 'gin::Widget', 'language': 'en'})
        change = self.proposal()['cards'][0]['changes'][0]
        self.assertEqual((change['kind'], change['name'], change['baseName']), ('display-name', 'Screen Element', 'Виджет'))

    def test_oed_file_is_the_one_the_site_publishes(self):
        result = self.call('atlas_export_oed', {'target': 'gin::Widget', 'path': str(self.root/'widget.oed')})
        self.assertEqual((self.root/'widget.oed').read_text(encoding='utf-8'), CARD['oed']['text'])
        self.assertEqual((result['confirmed'], result['drafts']), (1, 2))

    def test_oed_is_absent_for_a_class_with_nothing_to_export(self):
        self.atlas.site.shard('classes/aa.json')['classes']['1']['oed'] = None
        with self.assertRaises(ValueError): self.call('atlas_export_oed', {'target': 'gin::Widget'})

    def test_removing_a_record_is_a_proposal_that_can_be_taken_back(self):
        self.call('atlas_save_reference_record', {'target': 'gin::Widget', 'record_key': 'reference:1', 'confirmation': 'rejected'})
        self.assertEqual(self.proposal()['cards'][0]['changes'][0]['kind'], 'record-removal')
        self.call('atlas_restore_reference_record', {'target': 'gin::Widget', 'record_key': 'reference:1'})
        self.assertEqual(self.call('atlas_list_edits', {})['total'], 0)

    def test_exported_file_loads_back(self):
        self.call('atlas_set_method_documentation', {'method': 'gin::Widget::Paint', 'documentation': {'behavior': {'description': 'Новый'}}})
        before = self.proposal()
        self.call('atlas_discard_edits', {'all': True})
        self.call('atlas_import_edits', {'path': str(self.root/'out.json')})
        self.assertEqual(self.proposal()['cards'][0]['changes'], before['cards'][0]['changes'])

    def test_validation_finds_a_stale_edit(self):
        self.call('atlas_set_sender', {'nick': 'Sonnet 5.5'})
        self.call('atlas_set_class_documentation', {'target': 'gin::Widget', 'short_summary': 'Другое краткое описание'})
        self.assertTrue(self.call('atlas_validate_edits', {})['valid'])
        self.atlas.site.shards['classes/aa.json']['classes']['1']['publication']['hash'] = 'e'*64
        self.assertIn('изменилась', self.call('atlas_validate_edits', {})['problems'][0]['problem'])

    def test_sending_needs_consent_and_a_signature(self):
        self.call('atlas_set_class_documentation', {'target': 'gin::Widget', 'short_summary': 'Другое краткое описание'})
        with self.assertRaises(ValueError): self.call('atlas_send_edits', {'confirmed': False})
        with mock.patch.object(atlas_module, 'post_form') as post:
            self.assertFalse(self.call('atlas_send_edits', {'confirmed': True})['sent'])
            post.assert_not_called()

    def test_sending_posts_the_same_proposal_to_the_sites_form(self):
        self.call('atlas_set_sender', {'nick': 'Sonnet 5.5'})
        self.call('atlas_set_class_documentation', {'target': 'gin::Widget', 'short_summary': 'Другое краткое описание'})
        with mock.patch.object(atlas_module, 'post_form', return_value=(200, '')) as post:
            self.assertTrue(self.call('atlas_send_edits', {'confirmed': True})['sent'])
        url, fields = post.call_args.args
        self.assertEqual(url, 'https://docs.google.com/forms/d/e/ID/formResponse')
        self.assertEqual(json.loads(fields['entry.1'])['cards'][0]['className'], 'gin::Widget')


class BridgeTests(Base):
    def setUp(self):
        super().setUp()
        self.origin = 'https://octane-loader.utmsoft.ru'
        self.bridge = bridge.serve(self.store, self.origin, 0)
        self.addCleanup(self.bridge.server_close)
        self.addCleanup(self.bridge.shutdown)
        self.state = f'http://127.0.0.1:{self.bridge.server_port}/state'

    def open(self, method='GET', body=None, origin=None, host=None):
        request = Request(self.state, method=method, data=None if body is None else json.dumps(body).encode(), headers={'Origin': origin or self.origin, **({'Host': host} if host else {})})
        return urlopen(request)

    def test_only_the_site_is_answered(self):
        with self.open() as response:
            self.assertEqual(response.headers['Access-Control-Allow-Origin'], self.origin)
            self.assertEqual(json.load(response)['revision'], 0)
        for arguments in ({'origin': 'https://evil.example'}, {'host': 'evil.example:47615'}):
            with self.assertRaises(HTTPError) as error: self.open(**arguments)
            self.assertEqual(error.exception.code, 403)

    def test_browser_and_model_see_each_others_edits(self):
        self.call('atlas_set_method_purpose', {'method': 'gin::Widget::Hide', 'purpose': 'От модели'})
        with self.open() as response: state = json.load(response)
        self.assertIn('gin::Widget', state['edits']['cards'])
        state['edits']['sender']['nick'] = 'Человек'
        with self.open('PUT', {'baseRevision': state['revision'], 'edits': state['edits']}) as response: self.assertEqual(json.load(response)['revision'], state['revision'] + 1)
        self.assertEqual(self.call('atlas_list_edits', {})['sender']['nick'], 'Человек')

    def test_stale_browser_copy_is_refused_with_the_current_state(self):
        self.call('atlas_set_method_purpose', {'method': 'gin::Widget::Hide', 'purpose': 'От модели'})
        with self.assertRaises(HTTPError) as error: self.open('PUT', {'baseRevision': 0, 'edits': E.empty_edits()})
        self.assertEqual(error.exception.code, 409)
        self.assertIn('gin::Widget', json.load(error.exception)['edits']['cards'])


class ProtocolTests(Base):
    def test_a_real_client_lists_and_calls_tools(self):
        async def scenario():
            parameters = StdioServerParameters(command=sys.executable, args=['-m', 'engine_atlas_mcp', 'mcp', '--site', self.url, '--data', str(self.root/'data'), '--ghidra', 'http://127.0.0.1:1'], env=dict(os.environ))
            async with stdio_client(parameters) as (read, write), ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                self.assertEqual({tool.name for tool in tools.tools}, {item['name'] for item in server.tools()})
                result = await session.call_tool('atlas_status', {})
                status = json.loads(result.content[0].text)
                self.assertEqual(status['site'], self.url)
                self.assertFalse(status['ghidra']['ready'])
                failed = await session.call_tool('atlas_get_class', {'target': 'gin::Missing'})
                self.assertTrue(failed.isError)
        anyio.run(scenario)

    def test_every_tool_has_a_handler(self):
        call = server.dispatch(self.atlas)
        for item in server.tools():
            try: call(item['name'], {})
            except TypeError: pass
            except Exception as error: self.assertNotIn('Нет инструмента', str(error))


class GhidraTests(unittest.TestCase):
    def test_plain_error_when_ghidra_is_not_running(self):
        with self.assertRaises(GhidraError) as error: Ghidra('http://127.0.0.1:1').program()
        self.assertIn('Запусти Ghidra', str(error.exception))

    def test_wrong_file_or_base_is_named(self):
        self.assertEqual(FakeGhidra().check(0x10000)[1], [])
        self.assertTrue(FakeGhidra().check(0x20000)[1])


if __name__ == '__main__':
    unittest.main()
