# Dependency maintenance

The CLI and remote zipapp require Python 3.11+ and only the standard library.
NiceGUI remains optional and may be imported only inside `fettle/web/`.

Reviewed pins dated 2026-10-02 live in `constraints/dev.txt`, `web.txt`, and
`build.txt`, including resolved transitive dependencies. Project metadata specifies
supported ranges; constraints select the versions used for development and CI.
These are reviewed constraints, not hashes or a lock for every operating system.
Python and the operating system toolchain remain external prerequisites.

```sh
scripts/setup-dev.sh             # core development
FETTLE_DEV_ENV=venv-fettle-web scripts/setup-dev.sh --web  # stale-flag-ok: setup script option
python3 -m venv venv-nuitka-build
venv-nuitka-build/bin/python -m pip install -c constraints/build.txt --upgrade pip
venv-nuitka-build/bin/python -m pip install --build-constraint constraints/build.txt -c constraints/build.txt Nuitka
```

The tested selection is [pytest 9.1.1](https://pypi.org/project/pytest/9.1.1/),
[Ruff 0.16.10](https://pypi.org/project/ruff/0.16.10/),
[NiceGUI 3.17.1](https://pypi.org/project/nicegui/3.17.1/),
[Nuitka 4.2.2](https://pypi.org/project/Nuitka/4.2.2/), and
[setuptools 84.0.0](https://pypi.org/project/setuptools/84.0.0/).
Ruff retains `E4,E7,E9,F`; an upgrade does not expand lint policy.
Pytest 9 and NiceGUI 3 were already in the local environments. NiceGUI's tested
minimum is now 3.17.1, with its Python 3.14-compatible dependency requirements;
the experimental UI's HTTP and WebSocket guard is owned by fettle rather than
relying on framework defaults. Nuitka 4 is selected for the current Python 3.14
build environment. Setuptools 77+ supports the SPDX license metadata used here.

CI covers core Python 3.11–3.14 and optional-web tests on 3.11 and 3.14.
Only the release-upload job has `contents: write`; repairs refuse published releases.
Existing GitHub Actions major versions are retained: newer majors alone are not
evidence that a migration benefits this project.

To update, resolve in a fresh environment, review upstream release notes and
advisories, update relevant direct and transitive pins together, run `pip check`,
Ruff, core and optional-web tests, build/install packages, and exercise changed
browser paths with a harmless runner. Record outcomes and limitations in
[verification](maintenance-verification.md). Do not regenerate pins from a
long-lived environment or automate unreviewed dependency PRs.

Starlette 1.7 emits a deprecation warning for its HTTPX-based test client; the
current client still passes. A future test-client migration should be reviewed
with Starlette's release notes rather than added as an untested transitive package.

Native artifact builds additionally measure required GLIBC symbol versions across
bundled ELF objects. They require a C toolchain, Python development headers, patchelf,
and binutils (`readelf`); archive creation also requires zip. On Debian, install
`python3-dev gcc g++ make patchelf binutils zip` in the disposable build environment.
A rolling-host Python 3.14 build required glibc 2.44; a smoke pass
on that host did not make it portable to Debian 13. Release artifact jobs pin Ubuntu
24.04 to control that input, and generated RUNNING.md records each artifact's measured
requirement. See the portability results in [verification](maintenance-verification.md).
