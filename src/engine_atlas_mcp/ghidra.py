"""Decompilation through a running Ghidra with the Ghidra MCP plugin."""
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen

DEFAULT_URL = 'http://127.0.0.1:8089'
EXPECTED_NAME = 'libasphalt8.so'


class GhidraError(RuntimeError):
    pass


class Ghidra:
    def __init__(self, url=DEFAULT_URL):
        self.url = url.rstrip('/')

    def get(self, path, timeout=60, **parameters):
        query = urlencode({key: value for key, value in parameters.items() if value not in (None, '')})
        try:
            with urlopen(f'{self.url}{path}?{query}', timeout=timeout) as response: text = response.read().decode('utf-8', 'replace')
        except HTTPError as error:
            raise GhidraError(f'Ghidra ответила {error.code} на {path}: {error.read().decode("utf-8", "replace")[:300]}') from error
        except (URLError, OSError) as error:
            raise GhidraError(f'Ghidra не отвечает на {self.url}. Запусти Ghidra, открой {EXPECTED_NAME} в CodeBrowser и включи Ghidra MCP.') from error
        try: return json.loads(text)
        except ValueError: return text

    def program(self):
        info = self.get('/get_current_program_info', timeout=10)
        if not isinstance(info, dict) or 'name' not in info: raise GhidraError(f'В Ghidra не открыта программа: {str(info)[:200]}')
        return info

    def check(self, image_base):
        """The site's addresses hold only for the right file loaded at the right base."""
        info = self.program()
        problems = []
        if not str(info['name']).startswith(EXPECTED_NAME.split('.')[0]): problems.append(f'открыт {info["name"]}, нужен {EXPECTED_NAME}')
        if int(str(info.get('image_base', '0')), 16) != image_base: problems.append(f'база образа {info.get("image_base")}, нужна {image_base:x}')
        return info, problems

    def decompile(self, address):
        value = self.get('/decompile_function', address=f'0x{address:08X}', timeout=120)
        if isinstance(value, dict):
            for key in ('result', 'decompilation', 'decompiled', 'body', 'code', 'text'):
                if isinstance(value.get(key), str): return value[key]
            return json.dumps(value, ensure_ascii=False)
        return str(value)

    def callers(self, address, limit=50):
        return self.get('/get_function_callers', address=f'0x{address:08X}', limit=limit)

    def callees(self, address, limit=50):
        return self.get('/get_function_callees', address=f'0x{address:08X}', limit=limit)

    def function_at(self, address):
        return self.get('/get_function_by_address', address=f'0x{address:08X}')
