# Engine Atlas MCP

Engine Atlas MCP is a filling tool for [Engine Atlas](https://octane-loader.utmsoft.ru/en/reference/),
the reference for how the Asphalt 8 engine works. It gives your AI the site's edit mode:
whatever a person can do on a card, the model does through tools, and the research is saved
along with the edits.

[Русская версия](README.ru.md)

## The main idea

The community fills the reference. A person can edit cards on the site by hand, but studying
the engine by hand is slow. So your AI writes the edits and you look at the result.

The MCP stores nothing and publishes nothing. It is a working tool on top of the site:

- the model reads what the site already shows;
- it studies the game's code in your Ghidra;
- it fills cards in edit mode and records how it reached its conclusions;
- you check its work on the site and send it for review.

Notes and evidence travel with the edit. That is the point of working with an AI: you can see
how every conclusion was reached.

## How it works

```text
  your AI  ──MCP──>  engine-atlas-mcp  ──HTTPS──>  octane-loader.utmsoft.ru
                      │          │                 catalog, cards, languages
                      │          └────────────────  Ghidra on your computer
                      │                             the game's code
                      │  edits file
                      └───────────  browser with edit mode and My edits
```

Edits are shared: you see the AI's edits on the cards, the AI sees yours, and no page reload
is needed. The only local file holds edits you have not sent yet. There is no database and no
copy of the reference.

| What the model can do | |
|---|---|
| Read | classes, methods, properties, examples, notes and evidence in Russian and English |
| Search | class and function names, and the text of studied classes in a chosen language |
| Study | decompilation, callers and callees through Ghidra |
| Edit | articles, method purposes and details, properties, examples, evidence, translations, a class's readable name |
| Keep the research | notes, questions and hypotheses that travel with the edit |
| Manage edits | the My edits list, signature, comments, languages, validation, deletion |
| Export and send | OED files for mods, edit export and import, sending for review |

## What you need

- **Python 3.11** or newer.
- **An MCP client:** Claude Code, Codex, Antigravity or another.
- **Ghidra is required.** Cards are written from the real code, so you need
  [Ghidra](https://github.com/NationalSecurityAgency/ghidra) with the
  [Ghidra MCP](https://github.com/bethington/ghidra-mcp) plugin.
- **A browser:** Chrome, Edge or Firefox. Safari does not let the site reach your computer.

## Install

```sh
pip install git+https://github.com/mindkeyboard/engine-atlas-mcp
```

1. Download [`libasphalt8.so`](https://octane-loader.utmsoft.ru/downloads/libasphalt8.so)
   and open it in Ghidra. Keep the default import settings and wait for the analysis to
   finish. Then enable the Ghidra MCP plugin.
2. Connect the server to your client:
   **[instructions for Claude Code, Codex and Antigravity](docs/clients.md)**.
3. Check that everything is ready:

   ```sh
   engine-atlas-mcp doctor
   ```

   Every line should read `[ok]`.

## Use

From here on, it is plain requests. The model gets the working rules from the server.

1. **Ask it to study a class.**

   > Study the class gin::AspectRatioContainer in Engine Atlas.

2. **Open the edits on the site.** The model gives you a link like
   `https://octane-loader.utmsoft.ru/ru/reference/?view=edits&mcp=1`. The browser asks once
   for permission to reach devices on your local network: allow it. Change anything you like,
   and the model will see it.
3. **Have a second session check the work.** A different model is better:

   > You are the critic. Check my edits to gin::AspectRatioContainer by the critic role in the guide.

4. **Send the result.** Press Send on My edits, or tell the model:

   > Sign the edits with your name and send them for review.

Which models to use, and how to tell a good result from a bad one, is covered
[in the Engine Atlas documentation](https://octane-loader.utmsoft.ru/en/guide/octane-devtools/engine-atlas/mcp).

## Questions

**Where do edits live?** In the browser and in `~/.engine-atlas/edits.json` until you send
them. The server connects the file to the page through `127.0.0.1:47615`, which answers only
the site itself.

**Can I skip the browser?** Yes. The model can manage and send edits by itself. The site is
for looking at them.

**What is OED?** A file that passes what is known about a class to a mod's build. What is in
it and how to use it is explained [on the site](https://octane-loader.utmsoft.ru/en/guide/octane-devtools/engine-atlas/oed).

**A different site address?** `--site` or `ENGINE_ATLAS_SITE`; the Ghidra address is
`--ghidra` or `GHIDRA_MCP_URL`. Usually only site developers need this.

## License

[Apache-2.0](LICENSE). No game files are in this repository. This is an independent project,
not affiliated with Gameloft: see [NOTICE](NOTICE).
