# Подключение клиента

Сначала установите сервер, как описано в [README](../README.ru.md). После подключения команда
`engine-atlas-mcp doctor` покажет, готовы ли сайт и Ghidra.

Если клиент не находит `engine-atlas-mcp`, укажите полный путь. На Windows его покажет
`where engine-atlas-mcp`, на других системах `which engine-atlas-mcp`. В JSON и TOML
пишите пути с прямыми косыми чертами.

## Claude Code

```sh
claude mcp add --transport stdio --scope user engine-atlas -- engine-atlas-mcp mcp
```

`--scope user` подключает сервер во всех проектах. Без него он появится только в текущем.
Всё после `--` передаётся серверу без изменений.

Проверка: `claude mcp list` или `/mcp` внутри Claude Code. Сервер должен быть подключён.
Удаление: `claude mcp remove engine-atlas`.

Документация: [Connect Claude Code to tools via MCP](https://code.claude.com/docs/en/mcp).

## Codex

```sh
codex mcp add engine-atlas -- engine-atlas-mcp mcp
```

Либо добавьте это в `~/.codex/config.toml`. Этот файл общий для CLI, расширения IDE
и приложения:

```toml
[mcp_servers.engine-atlas]
command = "engine-atlas-mcp"
args = ["mcp"]
startup_timeout_sec = 60
```

`startup_timeout_sec` даёт медленным компьютерам больше стандартных 10 секунд. Проверка: `codex mcp list` или `/mcp`
внутри Codex.

Документация: [Model Context Protocol в Codex](https://developers.openai.com/codex/mcp),
[справочник настроек](https://developers.openai.com/codex/config-reference).

## Antigravity

Откройте файл настроек:

- **Antigravity IDE:** нажмите **…** вверху боковой панели агента, выберите
  **MCP Servers**, затем **Manage MCP Servers** и **View raw config**.
- **Antigravity CLI или вручную:** файл `~/.gemini/config/mcp_config.json`. Чтобы сервер
  работал только в одном проекте, используйте `<проект>/.agents/mcp_config.json`.

Добавьте сервер:

```json
{
  "mcpServers": {
    "engine-atlas": {
      "command": "engine-atlas-mcp",
      "args": ["mcp"]
    }
  }
}
```

Другие серверы в этом файле оставьте. Проверка: `/mcp` в Antigravity CLI или **Refresh**
в разделе **Installed MCP Servers** в приложении.

Документация: [Antigravity MCP](https://antigravity.google/docs/mcp).

## Другие клиенты

Любой клиент MCP может запустить сервер через stdio такой командой:

```sh
engine-atlas-mcp mcp
```

## Если что-то не работает

| Что случилось | Что делать |
|---|---|
| Сервер не запускается | Выполните `engine-atlas-mcp doctor`, затем `engine-atlas-mcp mcp` в терминале и прочитайте ошибку |
| `command not found` | Укажите полный путь к `engine-atlas-mcp` |
| Истекло время ожидания при запуске | Увеличьте время запуска в настройках клиента |
| Не работает декомпиляция | Запустите Ghidra, откройте `libasphalt8.so`, включите Ghidra MCP; если адрес не `http://127.0.0.1:8089`, передайте `--ghidra` |
| Сайт не видит MCP | Запустите сессию клиента, откройте ссылку на правки из `engine-atlas-mcp doctor`, разрешите доступ к локальной сети; Safari не подойдёт |
| Сайт недоступен или данные старые | Откройте сайт в браузере; `engine-atlas-mcp doctor` покажет причину |
| Инструменты не найдены | Перезапустите сессию клиента после добавления сервера |
