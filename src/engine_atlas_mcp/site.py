"""Read the published Engine Atlas: the same files the site's own pages load."""
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from . import __version__

DEFAULT_SITE = 'https://octane-loader.utmsoft.ru'
SHARDS_KEPT = 48
MANIFEST_SECONDS = 300
VIEWS = {'classes': 'classes/index.json', 'namespaces': 'namespaces.json', 'functions': 'functions/index.json'}


class SiteError(RuntimeError):
    pass


class Site:
    def __init__(self, url=DEFAULT_SITE):
        self.url = url.rstrip('/')
        parts = urlsplit(self.url)
        self.origin = f'{parts.scheme}://{parts.netloc}'
        self.lock = threading.RLock()
        self.loaded_at = 0
        self.current = None
        self.views = {}
        self.shards = OrderedDict()

    def get(self, path):
        request = Request(f'{self.url}/{path}', headers={'User-Agent': f'engine-atlas-mcp/{__version__}', 'Accept': 'application/json'})
        try:
            with urlopen(request, timeout=60) as response: return json.load(response)
        except HTTPError as error:
            raise SiteError(f'Сайт {self.url} ответил {error.code} на {path}.') from error
        except (URLError, OSError) as error:
            raise SiteError(f'Сайт {self.url} недоступен: {error}') from error
        except ValueError as error:
            raise SiteError(f'Сайт {self.url} вернул не JSON на {path}: похоже, там старая сборка.') from error

    def manifest(self):
        with self.lock:
            if self.current and time.monotonic() - self.loaded_at < MANIFEST_SECONDS: return self.current
            value = self.get('atlas/manifest.json')
            if not self.current or value.get('datasetId') != self.current.get('datasetId'):
                self.views, self.shards = {}, OrderedDict()
            self.current, self.loaded_at = value, time.monotonic()
            return value

    def data(self, path):
        return self.get(f'atlas/{self.manifest().get("datasetBase", "")}{path}')

    def view(self, name):
        manifest = self.manifest()
        with self.lock:
            if name not in self.views:
                self.views[name] = self.data(manifest.get('views', {}).get(name) or VIEWS[name])
            return self.views[name]

    @property
    def program(self):
        return self.manifest()['program']

    def classes(self):
        return self.view('classes')['classes']

    def namespaces(self):
        return self.view('namespaces')['namespaces']

    def function_namespaces(self):
        return self.view('functions')['namespaces']

    def publication(self):
        return self.get('publication.json')

    def shard(self, path):
        with self.lock:
            if path in self.shards:
                self.shards.move_to_end(path)
                return self.shards[path]
        value = self.data(path)
        with self.lock:
            self.shards[path] = value
            while len(self.shards) > SHARDS_KEPT: self.shards.popitem(last=False)
        return value

    def card(self, item):
        return self.shard(f'classes/{item["shard"]}.json')['classes'][str(item['id'])]

    def cards(self, items):
        with ThreadPoolExecutor(8) as pool: return list(pool.map(self.card, items))

    def free_functions(self, namespace):
        return self.shard(f'functions/{namespace["shard"]}.json')['functions']

    def resolve_class(self, target):
        """Exact names first; a short name works only while it stays unambiguous."""
        classes = self.classes()
        if isinstance(target, int) or str(target).isdigit():
            found = [item for item in classes if item['id'] == int(target)]
        else:
            text = str(target).strip()
            lowered = text.lower()
            found = [item for item in classes if item['name'] == text]
            found = found or [item for item in classes if item['name'].lower() == lowered]
            found = found or [item for item in classes if any(name.lower() == lowered for name in (item.get('displayNames') or {}).values())]
            found = found or [item for item in classes if item['name'].lower().endswith(f'::{lowered}')]
        if len(found) == 1: return found[0]
        if found: raise ValueError(f'Неоднозначное имя класса {target}: {", ".join(item["name"] for item in found[:10])}')
        raise ValueError(f'Класс {target} не найден. Используй atlas_search.')
