# Contributing

Research results do not go through pull requests. They are edits on the Engine Atlas site:
send them from My edits or ask the model to call `atlas_send_edits`.

For code, open an issue first if the change is large, then run the tests:

```sh
pip install -e .
python -m unittest discover -s tests
```

`src/engine_atlas_mcp/edits.py` mirrors the site's edit format. A change to that format
has to land on both sides. `research-guide-ru.md` is generated from the main project, so
fixes to it need to be reported as an issue.

Never commit game files, databases, decompiler dumps, keys or local paths.
