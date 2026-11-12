# Contributing to NoDPI

Thanks for your interest in NoDPI! Bug reports, site reports, ideas and pull
requests are all welcome. Issues and pull requests can be written in English or
Russian.

By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting problems

Use the issue templates:

- **The site doesn't work/open** — a specific site does not open through NoDPI.
- **Bug report** — NoDPI crashes, hangs or behaves incorrectly.
- **Feature request** — an idea for a new feature.
- **Ask a question** — anything else.

Please include:

- NoDPI version and how you run it (executable, source, Docker) with the full
  command line arguments;
- OS and browser;
- your internet provider and region, since blocking differs between providers;
- the error log (`--log-error error.log`) and, if relevant, the access log
  (`--log-access access.log`).

## Development setup

NoDPI uses only the Python standard library. No dependencies are needed to run it.

```bash
git clone https://github.com/GVCoder09/NoDPI.git
cd NoDPI
python3 src/main.py
```

Tools used for development:

- [ruff](https://docs.astral.sh/ruff/) for linting and formatting (`pip install ruff`);
- [PyInstaller](https://pyinstaller.org/) to build the executable (`pip install pyinstaller`).

## Project structure

```
src/
├── main.py              entry point (used by nodpi.spec and the Dockerfile)
└── nodpi/
    ├── app.py           wiring: arguments, components, startup
    ├── cli.py           command line arguments
    ├── config.py        ProxyConfig
    ├── interfaces.py    abstract interfaces
    ├── logger.py        access/error logs and console output
    ├── statistics.py    traffic and connection counters
    ├── updates.py       new version check
    ├── blacklist/       file, auto and "no blacklist" modes
    ├── proxy/           server, connection handling, HTTP, TLS fragmentation, desync
    ├── ui/              banner, live statistics, Windows tray
    └── autostart/       Windows registry and Linux systemd autostart
```

DPI bypass logic lives in `src/nodpi/proxy/`: `tls.py` parses and fragments
the ClientHello, `desync.py` contains the ways it is sent to the server.

## Code requirements

- **Python 3.8 compatibility.** Release builds use Python 3.8 to support
  Windows 7. Do not use newer syntax or library features (`match`,
  `list[str]` / `X | Y` type hints, etc.). Ruff is configured with
  `target-version = "py38"` and will not suggest them.
- **Standard library only.** Do not add third-party dependencies.
- **No administrator rights.** NoDPI must work for an unprivileged user on
  Windows, Linux and macOS. Use plain sockets only, no raw sockets or drivers.
- **Lint and format** before sending a pull request:

  ```bash
  ruff format
  ruff check
  ```

## Testing your changes

There are no automated tests yet, so check your change by hand:

1. Start the proxy, e.g. `python3 src/main.py --no-blacklist`.
2. Point a browser or `curl` at it:
   `curl -x http://127.0.0.1:8881 https://example.com/`.
3. Open sites that are blocked for you directly and make sure they open
   through NoDPI.
4. If you touched startup, logging or the console UI, also run with `-q` and
   with `--log-error` / `--log-access`.
5. If you touched anything that affects the build, check that
   `pyinstaller ./nodpi.spec` still produces a working executable.

Describe in the pull request what you tested, on which OS and provider.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Keep each pull request focused on one change. Refactoring and behavior
   changes are easier to review as separate pull requests.
3. Write commit titles in English, in the imperative mood, up to 50
   characters (e.g. `Fix crash when blacklist file is missing`).
4. Update `README.md` and `README.ru.md` if you add or change command line
   arguments or user-visible behavior.
5. Make sure `ruff format` and `ruff check` pass.

## License

By contributing, you agree that your contributions will be licensed under the
project's [GPL-3.0 license](LICENSE).
