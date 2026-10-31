"""Engine Atlas MCP: the site's edit mode as tools for an AI assistant.

Reads what octane-loader.utmsoft.ru publishes, decompiles through a local Ghidra, and
writes edits where the site's edit mode keeps them. Nothing is deployed locally.
"""
import argparse
import json
import os
from pathlib import Path

import anyio
from anyio import to_thread
from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from . import __version__
from .atlas import EVIDENCE_KINDS, LANGUAGES, NOTE_KINDS, RECORD_KINDS, Atlas
from .bridge import PORT, keep_serving
from .edits import EditStore
from .ghidra import DEFAULT_URL as DEFAULT_GHIDRA, Ghidra
from .site import DEFAULT_SITE, Site

DEFAULT_DATA = Path(os.environ.get('ENGINE_ATLAS_DATA', Path.home()/'.engine-atlas'))
SITE_URL = os.environ.get('ENGINE_ATLAS_SITE', DEFAULT_SITE)
GHIDRA_URL = os.environ.get('GHIDRA_MCP_URL', DEFAULT_GHIDRA)
INSTRUCTIONS = (
    'Engine Atlas целиком обслуживается этим MCP: отдельный навык не нужен. Данные читаются с сайта Engine Atlas, код — через Ghidra. '
    'Для исследования, редактуры или перевода: atlas_status → atlas_get_research_guide (полные правила) → atlas_get_research_tasks с target или namespace. '
    'Проверяющий чужие карточки работает по разделу «Роль критика» этого руководства. '
    'Все записи — это правки режима редактора: человек сразу видит их на сайте и может поправить, а ты видишь его изменения через atlas_get_edits. '
    'Ничего не публикуется само. atlas_send_edits вызывай только по прямой просьбе пользователя. Не удаляй заметки: они входят в правку.'
)

TARGET = {'target': {'type': ['string', 'integer'], 'description': 'Имя класса или его id'}}
METHOD = {'method': {'type': ['string', 'integer'], 'description': 'Полное или короткое имя метода, RVA либо адрес Ghidra'}}
LANGUAGE = {'language': {'type': 'string', 'enum': list(LANGUAGES)}}
CLASSES = {'classes': {'type': 'array', 'items': {'type': 'string'}, 'description': 'Только эти классы; по умолчанию все'}}
BODY = {'max_body_chars': {'type': 'integer', 'minimum': 500, 'maximum': 20000}}
METHODS = {'methods': {'type': 'array', 'maxItems': 32, 'items': {'type': ['string', 'integer', 'object']}}, **TARGET}
EVIDENCE = {'evidence': {'type': 'array', 'items': {'type': 'object'}, 'description': 'Основания: kind, reference, summary'}}
RECORD = {**TARGET, 'kind': {'type': 'string', 'enum': list(RECORD_KINDS)}, 'name': {'type': 'string'}, 'content': {'type': 'object'}, **LANGUAGE,
          'record_key': {'type': 'string', 'description': 'Ключ существующей записи или id новой'}, **EVIDENCE,
          'confirmation': {'type': 'string', 'enum': ['rejected'], 'description': 'rejected предлагает удалить запись'}}


def tool(name, description, properties=None, required=()):
    return {'name': name, 'description': description, 'inputSchema': {'type': 'object', 'properties': properties or {}, 'required': list(required), 'additionalProperties': False}}


def tools():
    return [
        tool('atlas_status', 'Сайт, версия данных, готовность Ghidra, число правок и ссылка на них на сайте.'),
        tool('atlas_search', 'Поиск по именам классов и свободных функций, по `Класс::метод`, а с in_text=true ещё и по опубликованным текстам изученных классов на выбранном языке.', {'query': {'type': 'string'}, 'kinds': {'type': 'array', 'items': {'type': 'string', 'enum': ['class', 'function']}}, **LANGUAGE, 'in_text': {'type': 'boolean'}, 'limit': {'type': 'integer'}}, ['query']),
        tool('atlas_list_namespaces', 'Пространства имён с числом классов и изученных.', {'query': {'type': 'string'}, 'limit': {'type': 'integer'}}),
        tool('atlas_list_classes', 'Список классов с отбором по namespace, имени и изученности.', {'namespace': {'type': 'string'}, 'studied_only': {'type': 'boolean'}, 'query': {'type': 'string'}, 'include_service': {'type': 'boolean'}, 'limit': {'type': 'integer'}, 'offset': {'type': 'integer'}}),
        tool('atlas_class_frontier', 'Неизученные классы, начиная с самых значимых по числу наследников.', {'limit': {'type': 'integer'}, 'namespace': {'type': 'string'}}),
        tool('atlas_get_class', 'Статья класса на выбранном языке, наследование, методы, записи и заметки, а также ещё не отправленные правки.', {**TARGET, **LANGUAGE, 'include_methods': {'type': 'boolean'}, 'include_research': {'type': 'boolean'}}, ['target']),
        tool('atlas_get_classes', 'До 16 классов разом. Ошибка одного не мешает остальным.', {'targets': {'type': 'array', 'maxItems': 16, 'items': {'type': ['string', 'integer']}}, **LANGUAGE, 'include_methods': {'type': 'boolean'}}, ['targets']),
        tool('atlas_get_structure', 'Устройство класса: базы, наследники, раскладка, поля, таблицы виртуальных методов.', TARGET, ['target']),
        tool('atlas_get_class_methods', 'Методы класса с адресами и назначением.', {**TARGET, **LANGUAGE, 'include_inherited': {'type': 'boolean'}, 'problems_only': {'type': 'boolean'}, 'query': {'type': 'string'}, 'limit': {'type': 'integer'}, 'offset': {'type': 'integer'}}, ['target']),
        tool('atlas_get_method', 'Полное описание метода или свободной функции на выбранном языке.', {**TARGET, **METHOD, **LANGUAGE}),
        tool('atlas_get_class_research', 'Свойства, отношения, примеры, основания и заметки класса.', {**TARGET, **LANGUAGE, 'include_inherited': {'type': 'boolean'}}, ['target']),
        tool('atlas_get_research_notes', 'Опубликованные заметки класса и заметки в неотправленных правках.', {**TARGET, **LANGUAGE}, ['target']),
        tool('atlas_get_research_tasks', 'Что осталось сделать: с target — пробелы класса с готовыми аргументами записи, с namespace — следующие классы.', {**TARGET, 'namespace': {'type': 'string'}, 'include_details': {'type': 'boolean'}, 'limit': {'type': 'integer'}, 'offset': {'type': 'integer'}}),
        tool('atlas_get_research_guide', 'Полные правила: исследование, смысл, основания, редактура, перевод и роль критика.'),
        tool('atlas_get_research_checklist', 'Короткий маршрут работы и справочник допустимых значений.', {'include_details': {'type': 'boolean'}}),
        tool('atlas_export_oed', 'Файл OED класса для модов, тот же, что по кнопке на сайте: подтверждённые привязки работают, заготовки методов остаются комментариями.', {**TARGET, 'path': {'type': 'string', 'description': 'Куда сохранить; по умолчанию папка выгрузок'}}, ['target']),
        tool('atlas_get_method_context', 'Декомпиляция из Ghidra, вызывающие и вызываемые функции и всё, что известно о методе.', {**TARGET, **METHOD, **LANGUAGE, 'include_body': {'type': 'boolean'}, **BODY}),
        tool('atlas_get_method_contexts', 'Контексты до 32 методов, ошибки у каждого свои.', {**METHODS, **LANGUAGE, 'include_body': {'type': 'boolean'}, **BODY}, ['methods']),
        tool('atlas_get_method_bodies', 'Только декомпиляция до 32 методов.', {**METHODS, **BODY}, ['methods']),
        tool('atlas_set_class_documentation', 'Правка статьи класса. Появляется на карточке в режиме редактора.', {**TARGET, **LANGUAGE, 'short_summary': {'type': 'string', 'maxLength': 240}, 'developer_description': {'type': 'string'}}, ['target']),
        tool('atlas_set_class_display_name', 'Читаемое имя класса вместо неудобного имени C++: одно на оба языка и только латиницей. Это не перевод: не превращай PlayerProfile в «Профиль игрока». Пустая строка убирает имя.', {**TARGET, 'name': {'type': 'string', 'maxLength': 120}}, ['target', 'name']),
        tool('atlas_set_method_purpose', 'Правка короткого назначения метода, до 180 знаков.', {**TARGET, **METHOD, 'purpose': {'type': 'string', 'maxLength': 180}, **LANGUAGE}, ['purpose']),
        tool('atlas_set_method_purposes', 'Назначения до 100 методов одного класса разом.', {**TARGET, 'items': {'type': 'array', 'maxItems': 100, 'items': {'type': 'object'}}, **LANGUAGE}, ['target', 'items']),
        tool('atlas_set_method_documentation', 'Правка подробностей метода: summary, behavior, parameters, returns, instance_acquisition, thread, ownership, invalidation, preconditions, postconditions, side_effects, repeatability, example, evidence. Перевод — с language=en.', {**TARGET, **METHOD, 'documentation': {'type': 'object'}, **LANGUAGE}, ['documentation']),
        tool('atlas_save_reference_record', 'Правка или новая запись: свойство, поле, отношение, условия, пример. Значение confirmation=rejected предлагает удалить запись.', RECORD, ['target']),
        tool('atlas_save_reference_records', 'До 200 записей разом: при ошибке не сохраняется ни одна.', {'items': {'type': 'array', 'maxItems': 200, 'items': {'type': 'object'}}}, ['items']),
        tool('atlas_restore_reference_record', 'Отменить предложение удалить запись.', {**TARGET, 'record_key': {'type': 'string'}}, ['target', 'record_key']),
        tool('atlas_remove_new_record', 'Убрать ещё не отправленную новую запись.', {**TARGET, 'record_key': {'type': 'string'}}, ['target', 'record_key']),
        tool('atlas_add_evidence', 'Добавить основание к методу или записи. Для метода адрес подставится сам.', {**TARGET, 'owner': {'type': 'string', 'enum': ['method', 'record']}, 'id': {'type': 'string', 'description': 'Метод или ключ записи'}, 'kind': {'type': 'string', 'enum': list(EVIDENCE_KINDS)}, 'reference': {'type': 'string'}, 'summary': {'type': 'string'}}, ['target', 'owner', 'id', 'summary']),
        tool('atlas_save_research_note', 'Сохранить наблюдение, вопрос, предположение или результат. Заметки входят в правку.', {**TARGET, 'text': {'type': 'string'}, 'kind': {'type': 'string', 'enum': list(NOTE_KINDS)}, **LANGUAGE}, ['target', 'text']),
        tool('atlas_list_edits', 'Список правок как на странице «Мои правки»: классы, виды, язык, комментарий, подпись. Включает всё, что человек изменил на сайте.'),
        tool('atlas_get_edits', 'Полный текст правок класса рядом с опубликованным текстом.', TARGET, ['target']),
        tool('atlas_set_sender', 'Подпись всей отправки: ник, контакт и кто правил.', {'nick': {'type': 'string'}, 'contact': {'type': 'string'}, 'role': {'type': 'string', 'enum': ['ai', 'human']}}),
        tool('atlas_set_edit_options', 'Комментарий к правке класса и языки, которые уйдут в отправку.', {**TARGET, 'comment': {'type': 'string'}, 'language': {'type': 'string', 'enum': ['all', 'ru', 'en']}}, ['target']),
        tool('atlas_discard_edits', 'Удалить правки классов насовсем. Только по просьбе пользователя.', {**CLASSES, 'all': {'type': 'boolean'}}),
        tool('atlas_validate_edits', 'Проверить правки: устаревшие редакции, пропавшие методы, размеры, подпись.', CLASSES),
        tool('atlas_export_edits', 'Сохранить правки в JSON-файл в формате отправки.', {**CLASSES, 'path': {'type': 'string'}}),
        tool('atlas_import_edits', 'Загрузить JSON-файл правок.', {'path': {'type': 'string'}}, ['path']),
        tool('atlas_send_edits', 'Отправить правки на рассмотрение через форму сайта. Только по прямой просьбе пользователя: отправка разрешает публикацию с его ником.', {**CLASSES, 'confirmed': {'type': 'boolean'}}, ['confirmed']),
        tool('atlas_batch', 'До 200 вызовов этих инструментов по порядку, один результат на вызов.', {'requests': {'type': 'array', 'maxItems': 200, 'items': {'type': 'object'}}, 'stop_on_error': {'type': 'boolean'}}, ['requests']),
    ]


def dispatch(atlas):
    def rename(action, **names):
        return lambda **arguments: action(**{names.get(key, key): value for key, value in arguments.items()})
    table = {
        'atlas_status': atlas.status, 'atlas_search': atlas.search, 'atlas_list_namespaces': atlas.list_namespaces, 'atlas_list_classes': atlas.list_classes, 'atlas_class_frontier': atlas.frontier,
        'atlas_get_class': atlas.get_class, 'atlas_get_classes': atlas.get_classes, 'atlas_get_structure': atlas.get_structure, 'atlas_get_class_methods': atlas.get_class_methods, 'atlas_get_method': atlas.get_method,
        'atlas_get_class_research': atlas.get_class_research, 'atlas_get_research_notes': atlas.get_research_notes, 'atlas_get_research_tasks': atlas.research_tasks,
        'atlas_get_research_guide': atlas.guide, 'atlas_get_research_checklist': atlas.checklist, 'atlas_get_method_context': atlas.method_context, 'atlas_get_method_contexts': atlas.method_contexts, 'atlas_get_method_bodies': atlas.method_bodies,
        'atlas_set_class_documentation': atlas.set_class_documentation, 'atlas_set_class_display_name': atlas.set_display_name, 'atlas_export_oed': atlas.export_oed, 'atlas_set_method_purpose': atlas.set_method_purpose, 'atlas_set_method_purposes': atlas.set_method_purposes, 'atlas_set_method_documentation': atlas.set_method_documentation,
        'atlas_save_reference_record': atlas.save_reference_record, 'atlas_save_reference_records': atlas.save_reference_records, 'atlas_restore_reference_record': atlas.restore_reference_record, 'atlas_remove_new_record': atlas.remove_new_record,
        'atlas_add_evidence': rename(atlas.add_evidence, id='identifier'), 'atlas_save_research_note': atlas.save_note, 'atlas_list_edits': atlas.list_edits, 'atlas_get_edits': atlas.get_edits,
        'atlas_set_sender': atlas.set_sender, 'atlas_set_edit_options': atlas.set_options, 'atlas_discard_edits': rename(atlas.discard, all='everything'), 'atlas_validate_edits': atlas.validate,
        'atlas_export_edits': atlas.export, 'atlas_import_edits': atlas.import_file, 'atlas_send_edits': atlas.send,
    }

    def batch(requests, stop_on_error=False):
        results = []
        for request in requests[:200]:
            try: results.append({'tool': request['tool'], 'result': call(request['tool'], request.get('arguments') or {})})
            except Exception as error:
                results.append({'tool': request.get('tool'), 'error': str(error)})
                if stop_on_error: break
        return {'results': results}

    def call(name, arguments):
        if name == 'atlas_batch': return batch(**arguments)
        if name not in table: raise ValueError(f'Нет инструмента {name}.')
        return table[name](**arguments)
    return call


def run(atlas):
    call = dispatch(atlas)
    server = Server('engine-atlas', version=__version__, instructions=INSTRUCTIONS)

    @server.list_tools()
    async def list_tools():
        return [types.Tool(**item) for item in tools()]

    @server.call_tool()
    async def call_tool(name, arguments):
        # Network and Ghidra calls block, and the client must stay responsive meanwhile.
        result = await to_thread.run_sync(lambda: call(name, arguments or {}))
        return [types.TextContent(type='text', text=json.dumps(result, ensure_ascii=False, indent=2, default=str))]

    async def serve():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    anyio.run(serve)


def build(args, bridge=None):
    site, ghidra = Site(args.site), Ghidra(args.ghidra)
    return Atlas(site, EditStore(Path(args.data)/'edits.json'), ghidra, bridge, args.data)


def doctor(args):
    """Say plainly what is ready, so a failed connection is not a mystery."""
    atlas = build(args)
    rows = []
    try:
        counts = atlas.site.manifest()['counts']
        rows.append(('Сайт', True, f'{atlas.site.url}: {counts["classes"]} классов, изучено {counts["studiedClasses"]}'))
    except Exception as error:
        rows.append(('Сайт', False, str(error)))
    try:
        state = atlas.ghidra_state()
        rows.append(('Ghidra', state['ready'], state.get('program') or '; '.join(state['problems'])))
        if state.get('program') and state['problems']: rows[-1] = ('Ghidra', False, '; '.join(state['problems']))
    except Exception as error:
        rows.append(('Ghidra', False, str(error)))
    rows.append(('Правки', True, str(atlas.store.path)))
    for name, ready, detail in rows: print(f'[{"ok" if ready else "нет"}] {name}: {detail}')
    print(f'Правки на сайте: {atlas.edits_url}')
    return all(ready for _, ready, _ in rows)


def main():
    parser = argparse.ArgumentParser(prog='engine-atlas-mcp', description=__doc__.splitlines()[0])
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='command', required=True)
    serve = commands.add_parser('mcp', help='Run the MCP server over stdio')
    check = commands.add_parser('doctor', help='Check the site and Ghidra')
    for command in (serve, check):
        command.add_argument('--site', default=SITE_URL); command.add_argument('--ghidra', default=GHIDRA_URL)
        command.add_argument('--data', type=Path, default=DEFAULT_DATA)
    args = parser.parse_args()
    if args.command == 'doctor': raise SystemExit(0 if doctor(args) else 1)
    store = EditStore(Path(args.data)/'edits.json')
    run(build(args, keep_serving(store, Site(args.site).origin, PORT)))


if __name__ == '__main__': main()
