# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.415410197831000");
  script_cve_id("CVE-2025-62518");
  script_tag(name:"creation_date", value:"2025-11-05 04:06:44 +0000 (Wed, 05 Nov 2025)");
  script_version("2025-11-05T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-11-05 05:40:07 +0000 (Wed, 05 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-4154ea83d0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-4154ea83d0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-4154ea83d0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2360699");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2371174");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2395006");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2395167");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398117");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398118");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2398161");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2400050");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2400578");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2400943");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2401013");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2401022");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2401408");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2401439");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402439");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402441");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402442");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402443");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402479");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402494");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402517");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402725");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402881");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402923");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403079");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403294");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403490");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403670");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403839");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2404080");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2404311");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2404693");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2404731");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2405079");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2405080");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2405109");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2405172");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2406135");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2406610");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2406784");
  script_xref(name:"URL", value:"https://fastapi.tiangolo.com/advanced/advanced-dependencies#dependencies-with-yield-httpexception-except-and-background-tasks");
  script_xref(name:"URL", value:"https://github.com/Kludex/starlette/security/advisories/GHSA-7f5h-v6xp-fcq8");
  script_xref(name:"URL", value:"https://github.com/PyO3/maturin/blob/v1.9.6/Changelog.md");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-j5gw-2vrg-8fgx");
  script_xref(name:"URL", value:"https://github.com/astral-sh/ruff/blob/0.14.2/CHANGELOG.md");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/blob/0.9.5/CHANGELOG.md");
  script_xref(name:"URL", value:"https://github.com/fastapi/annotated-doc");
  script_xref(name:"URL", value:"https://github.com/pydantic/jiter/releases/tag/v0.11.0");
  script_xref(name:"URL", value:"https://github.com/pydantic/pydantic-extra-types/releases/tag/v2.10.6");
  script_xref(name:"URL", value:"https://pydantic.dev/articles/pydantic-v2-12-release");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fastapi-cli, fastapi-cloud-cli, gherkin, maturin, openapi-python-client, python-annotated-doc, python-cron-converter, python-fastapi, python-inline-snapshot, python-jiter, python-openapi-core, python-platformio, python-pydantic, python-pydantic-core, python-pydantic-extra-types, python-rignore, python-starlette, python-typer, python-typing-inspection, python-uv-build, ruff, rust-astral-tokio-tar, rust-attribute-derive, rust-attribute-derive-macro, rust-collection_literals, rust-get-size2, rust-get-size-derive2, rust-interpolator, rust-jiter, rust-manyhow, rust-manyhow-macros, rust-proc-macro-utils, rust-quote-use, rust-quote-use-macros, rust-regex, rust-regex-automata, rust-reqsign, rust-reqsign-aws-v4, rust-reqsign-command-execute-tokio, rust-reqsign-core, rust-reqsign-file-read-tokio, rust-reqsign-http-send-reqwest, rust-serde_json, rust-speedate, rust-tikv-jemalloc-sys, rust-tikv-jemallocator, uv' package(s) announced via the FEDORA-2025-4154ea83d0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## uv / python-uv-build 0.9.5

[link moved to references]

----

## ruff 0.14.2

[link moved to references]

----

## Pydantic 2.12.3

[Blog post]([link moved to references])

----

## maturin 1.9.6

[link moved to references]

----

## python-typing-inspection 0.4.2 (2025-10-01)

- Add `typing_objects.is_noextraitems()`

----

## python-jiter 0.11.0

[link moved to references]

----

## python-pydantic-extra-types 2.10.6

[link moved to references]

----

# Typer

## 0.20.0

### Features

* Enable command suggestions on typo by default.

### Upgrades

* Add (official) support for Python 3.14.

### Internal

Assorted small enhancements.

----

# FastAPI

## 0.120.1

### Upgrades

* Bump Starlette to <`0.50.0`.

### Internal

* Add `license` and `license-files` to `pyproject.toml`, remove `License` from `classifiers`.

## 0.120.0

There are no major nor breaking changes in this release.

The internal reference documentation now uses `annotated_doc.Doc` instead of `typing_extensions.Doc`, this adds a new (very small) dependency on [`annotated-doc`]([link moved to references]), a package made just to provide that `Doc` documentation utility class.

I would expect `typing_extensions.Doc` to be deprecated and then removed at some point from `typing_extensions`, for that reason there's the new `annotated-doc` micro-package. If you are curious about this, you can read more in the repo for [`annotated-doc`]([link moved to references]).

This new version `0.120.0` only contains that transition to the new home package for that utility class `Doc`.

### Translations, Internal

Assorted improvements.

## 0.119.1

### Fixes

* Fix internal Pydantic v1 compatibility (warnings) for Python 3.14 and Pydantic 2.12.1.

### Docs, Internal

Assorted improvements.

## 0.119.0

FastAPI now (temporarily) supports both Pydantic v2 models and `pydantic.v1` models at the same time in the same app, to make it easier for any FastAPI apps still using Pydantic v1 to gradually but quickly **migrate to Pydantic v2**.

### Features

* Add support for `from pydantic.v1 import BaseModel`, mixed Pydantic v1 and v2 models in the same app.

## 0.118.3

### Upgrades

- Add (official) support for Python 3.14.

## 0.118.2

### Fixes

* Fix tagged discriminated union not recognized as body field.

## 0.118.1

### Upgrades

* Ensure compatibility with Pydantic 2.12.0.

### Docs, Translations, Internal

Assorted bugfixes and enhancements.

## 0.118.0

### Fixes

* Fix support for `StreamingResponse`s with dependencies with `yield` or `UploadFile`s, close after the response is done.

Before FastAPI 0.118.0, if you used a dependency with `yield`, it would run the exit code after the *path operation function* returned but right before sending the response.

This change also meant that if you returned a `StreamingResponse`, the exit code of the dependency with `yield` would have been already run.

For example, if you ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'fastapi-cli, fastapi-cloud-cli, gherkin, maturin, openapi-python-client, python-annotated-doc, python-cron-converter, python-fastapi, python-inline-snapshot, python-jiter, python-openapi-core, python-platformio, python-pydantic, python-pydantic-core, python-pydantic-extra-types, python-rignore, python-starlette, python-typer, python-typing-inspection, python-uv-build, ruff, rust-astral-tokio-tar, rust-attribute-derive, rust-attribute-derive-macro, rust-collection_literals, rust-get-size2, rust-get-size-derive2, rust-interpolator, rust-jiter, rust-manyhow, rust-manyhow-macros, rust-proc-macro-utils, rust-quote-use, rust-quote-use-macros, rust-regex, rust-regex-automata, rust-reqsign, rust-reqsign-aws-v4, rust-reqsign-command-execute-tokio, rust-reqsign-core, rust-reqsign-file-read-tokio, rust-reqsign-http-send-reqwest, rust-serde_json, rust-speedate, rust-tikv-jemalloc-sys, rust-tikv-jemallocator, uv' package(s) on Fedora 43.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"fastapi-cli+standard", rpm:"fastapi-cli+standard~0.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fastapi-cli+standard-no-fastapi-cloud-cli", rpm:"fastapi-cli+standard-no-fastapi-cloud-cli~0.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fastapi-cli", rpm:"fastapi-cli~0.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fastapi-cli-slim+standard", rpm:"fastapi-cli-slim+standard~0.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fastapi-cli-slim+standard-no-fastapi-cloud-cli", rpm:"fastapi-cli-slim+standard-no-fastapi-cloud-cli~0.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fastapi-cli-slim", rpm:"fastapi-cli-slim~0.0.14~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fastapi-cloud-cli+standard", rpm:"fastapi-cloud-cli+standard~0.3.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fastapi-cloud-cli", rpm:"fastapi-cloud-cli~0.3.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin", rpm:"gherkin~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-c-devel", rpm:"gherkin-c-devel~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-c-libs", rpm:"gherkin-c-libs~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-c-libs-debuginfo", rpm:"gherkin-c-libs-debuginfo~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-cpp-devel", rpm:"gherkin-cpp-devel~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-cpp-libs", rpm:"gherkin-cpp-libs~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-cpp-libs-debuginfo", rpm:"gherkin-cpp-libs-debuginfo~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-cpp-tools", rpm:"gherkin-cpp-tools~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-cpp-tools-debuginfo", rpm:"gherkin-cpp-tools-debuginfo~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-data", rpm:"gherkin-data~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-debuginfo", rpm:"gherkin-debuginfo~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gherkin-debugsource", rpm:"gherkin-debugsource~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin", rpm:"maturin~1.9.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin-debuginfo", rpm:"maturin-debuginfo~1.9.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"maturin-debugsource", rpm:"maturin-debugsource~1.9.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openapi-python-client", rpm:"openapi-python-client~0.26.2~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"platformio", rpm:"platformio~6.1.18~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-annotated-doc", rpm:"python-annotated-doc~0.0.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cron-converter", rpm:"python-cron-converter~1.2.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-fastapi", rpm:"python-fastapi~0.120.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-inline-snapshot", rpm:"python-inline-snapshot~0.30.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-jiter", rpm:"python-jiter~0.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-jiter-debugsource", rpm:"python-jiter-debugsource~0.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-openapi-core", rpm:"python-openapi-core~0.19.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-platformio", rpm:"python-platformio~6.1.18~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pydantic", rpm:"python-pydantic~2.12.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pydantic-core", rpm:"python-pydantic-core~2.41.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pydantic-core-debugsource", rpm:"python-pydantic-core-debugsource~2.41.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pydantic-doc", rpm:"python-pydantic-doc~2.12.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pydantic-extra-types", rpm:"python-pydantic-extra-types~2.10.6~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rignore", rpm:"python-rignore~0.7.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rignore-debugsource", rpm:"python-rignore-debugsource~0.7.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-starlette", rpm:"python-starlette~0.49.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-typer", rpm:"python-typer~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-typing-inspection", rpm:"python-typing-inspection~0.4.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build", rpm:"python-uv-build~0.9.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build-debugsource", rpm:"python-uv-build-debugsource~0.9.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-annotated-doc", rpm:"python3-annotated-doc~0.0.3~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cron-converter", rpm:"python3-cron-converter~1.2.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi+all", rpm:"python3-fastapi+all~0.120.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi", rpm:"python3-fastapi~0.120.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi-slim+all", rpm:"python3-fastapi-slim+all~0.120.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi-slim+standard", rpm:"python3-fastapi-slim+standard~0.120.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi-slim+standard-no-fastapi-cloud-cli", rpm:"python3-fastapi-slim+standard-no-fastapi-cloud-cli~0.120.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fastapi-slim", rpm:"python3-fastapi-slim~0.120.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gherkin-official", rpm:"python3-gherkin-official~35.1.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-inline-snapshot+black", rpm:"python3-inline-snapshot+black~0.30.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-inline-snapshot+dirty-equals", rpm:"python3-inline-snapshot+dirty-equals~0.30.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-inline-snapshot", rpm:"python3-inline-snapshot~0.30.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jiter", rpm:"python3-jiter~0.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-jiter-debuginfo", rpm:"python3-jiter-debuginfo~0.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+aiohttp", rpm:"python3-openapi-core+aiohttp~0.19.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+django", rpm:"python3-openapi-core+django~0.19.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+falcon", rpm:"python3-openapi-core+falcon~0.19.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+fastapi", rpm:"python3-openapi-core+fastapi~0.19.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+flask", rpm:"python3-openapi-core+flask~0.19.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+requests", rpm:"python3-openapi-core+requests~0.19.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core+starlette", rpm:"python3-openapi-core+starlette~0.19.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-openapi-core", rpm:"python3-openapi-core~0.19.5~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-platformio", rpm:"python3-platformio~6.1.18~7.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic+email", rpm:"python3-pydantic+email~2.12.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic+timezone", rpm:"python3-pydantic+timezone~2.12.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic", rpm:"python3-pydantic~2.12.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-core", rpm:"python3-pydantic-core~2.41.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-core-debuginfo", rpm:"python3-pydantic-core-debuginfo~2.41.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-extra-types+all", rpm:"python3-pydantic-extra-types+all~2.10.6~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-extra-types+cron", rpm:"python3-pydantic-extra-types+cron~2.10.6~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-extra-types+pendulum", rpm:"python3-pydantic-extra-types+pendulum~2.10.6~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-extra-types+phonenumbers", rpm:"python3-pydantic-extra-types+phonenumbers~2.10.6~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-extra-types+pycountry", rpm:"python3-pydantic-extra-types+pycountry~2.10.6~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-extra-types+python_ulid", rpm:"python3-pydantic-extra-types+python_ulid~2.10.6~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-extra-types+semver", rpm:"python3-pydantic-extra-types+semver~2.10.6~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pydantic-extra-types", rpm:"python3-pydantic-extra-types~2.10.6~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rignore", rpm:"python3-rignore~0.7.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rignore-debuginfo", rpm:"python3-rignore-debuginfo~0.7.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ruff", rpm:"python3-ruff~0.14.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-starlette+full", rpm:"python3-starlette+full~0.49.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-starlette", rpm:"python3-starlette~0.49.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-typer", rpm:"python3-typer~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-typer-cli", rpm:"python3-typer-cli~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-typer-slim+standard", rpm:"python3-typer-slim+standard~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-typer-slim", rpm:"python3-typer-slim~0.20.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-typing-inspection", rpm:"python3-typing-inspection~0.4.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv", rpm:"python3-uv~0.9.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build", rpm:"python3-uv-build~0.9.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build-debuginfo", rpm:"python3-uv-build-debuginfo~0.9.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff", rpm:"ruff~0.14.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff-debuginfo", rpm:"ruff-debuginfo~0.14.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff-debugsource", rpm:"ruff-debugsource~0.14.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar+default-devel", rpm:"rust-astral-tokio-tar+default-devel~0.5.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar+xattr-devel", rpm:"rust-astral-tokio-tar+xattr-devel~0.5.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar", rpm:"rust-astral-tokio-tar~0.5.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar-devel", rpm:"rust-astral-tokio-tar-devel~0.5.6~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive+default-devel", rpm:"rust-attribute-derive+default-devel~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive+syn-full-devel", rpm:"rust-attribute-derive+syn-full-devel~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive", rpm:"rust-attribute-derive~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive-devel", rpm:"rust-attribute-derive-devel~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive-macro+default-devel", rpm:"rust-attribute-derive-macro+default-devel~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive-macro", rpm:"rust-attribute-derive-macro~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive-macro-devel", rpm:"rust-attribute-derive-macro-devel~0.10.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-collection_literals+default-devel", rpm:"rust-collection_literals+default-devel~1.0.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-collection_literals", rpm:"rust-collection_literals~1.0.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-collection_literals-devel", rpm:"rust-collection_literals-devel~1.0.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size-derive2+default-devel", rpm:"rust-get-size-derive2+default-devel~0.7.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size-derive2", rpm:"rust-get-size-derive2~0.7.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size-derive2-devel", rpm:"rust-get-size-derive2-devel~0.7.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+bytes-devel", rpm:"rust-get-size2+bytes-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+chrono-devel", rpm:"rust-get-size2+chrono-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+chrono-tz-devel", rpm:"rust-get-size2+chrono-tz-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+compact-str-devel", rpm:"rust-get-size2+compact-str-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+default-devel", rpm:"rust-get-size2+default-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+derive-devel", rpm:"rust-get-size2+derive-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+get-size-derive2-devel", rpm:"rust-get-size2+get-size-derive2-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+hashbrown-devel", rpm:"rust-get-size2+hashbrown-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+indexmap-devel", rpm:"rust-get-size2+indexmap-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+smallvec-devel", rpm:"rust-get-size2+smallvec-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+thin-vec-devel", rpm:"rust-get-size2+thin-vec-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+url-devel", rpm:"rust-get-size2+url-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2", rpm:"rust-get-size2~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2-devel", rpm:"rust-get-size2-devel~0.7.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator+debug-devel", rpm:"rust-interpolator+debug-devel~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator+default-devel", rpm:"rust-interpolator+default-devel~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator+iter-devel", rpm:"rust-interpolator+iter-devel~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator+number-devel", rpm:"rust-interpolator+number-devel~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator+pointer-devel", rpm:"rust-interpolator+pointer-devel~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator", rpm:"rust-interpolator~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator-devel", rpm:"rust-interpolator-devel~0.5.0~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jiter+default-devel", rpm:"rust-jiter+default-devel~0.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jiter+num-bigint-devel", rpm:"rust-jiter+num-bigint-devel~0.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jiter+python-devel", rpm:"rust-jiter+python-devel~0.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jiter", rpm:"rust-jiter~0.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-jiter-devel", rpm:"rust-jiter-devel~0.11.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+darling-devel", rpm:"rust-manyhow+darling-devel~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+darling_core-devel", rpm:"rust-manyhow+darling_core-devel~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+default-devel", rpm:"rust-manyhow+default-devel~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+macros-devel", rpm:"rust-manyhow+macros-devel~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+syn-devel", rpm:"rust-manyhow+syn-devel~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+syn1-devel", rpm:"rust-manyhow+syn1-devel~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+syn2-devel", rpm:"rust-manyhow+syn2-devel~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow", rpm:"rust-manyhow~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow-devel", rpm:"rust-manyhow-devel~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow-macros+default-devel", rpm:"rust-manyhow-macros+default-devel~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow-macros", rpm:"rust-manyhow-macros~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow-macros-devel", rpm:"rust-manyhow-macros-devel~0.11.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+default-devel", rpm:"rust-proc-macro-utils+default-devel~0.10.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+parser-devel", rpm:"rust-proc-macro-utils+parser-devel~0.10.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+proc-macro-devel", rpm:"rust-proc-macro-utils+proc-macro-devel~0.10.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+proc-macro2-devel", rpm:"rust-proc-macro-utils+proc-macro2-devel~0.10.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+quote-devel", rpm:"rust-proc-macro-utils+quote-devel~0.10.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+smallvec-devel", rpm:"rust-proc-macro-utils+smallvec-devel~0.10.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils", rpm:"rust-proc-macro-utils~0.10.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils-devel", rpm:"rust-proc-macro-utils-devel~0.10.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use+default-devel", rpm:"rust-quote-use+default-devel~0.8.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use+syn-devel", rpm:"rust-quote-use+syn-devel~0.8.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use", rpm:"rust-quote-use~0.8.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use-devel", rpm:"rust-quote-use-devel~0.8.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use-macros+default-devel", rpm:"rust-quote-use-macros+default-devel~0.8.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use-macros", rpm:"rust-quote-use-macros~0.8.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use-macros-devel", rpm:"rust-quote-use-macros-devel~0.8.4~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+default-devel", rpm:"rust-regex+default-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+logging-devel", rpm:"rust-regex+logging-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+pattern-devel", rpm:"rust-regex+pattern-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-backtrack-devel", rpm:"rust-regex+perf-backtrack-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-cache-devel", rpm:"rust-regex+perf-cache-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-devel", rpm:"rust-regex+perf-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-dfa-devel", rpm:"rust-regex+perf-dfa-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-dfa-full-devel", rpm:"rust-regex+perf-dfa-full-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-inline-devel", rpm:"rust-regex+perf-inline-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-literal-devel", rpm:"rust-regex+perf-literal-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-onepass-devel", rpm:"rust-regex+perf-onepass-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+std-devel", rpm:"rust-regex+std-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-age-devel", rpm:"rust-regex+unicode-age-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-bool-devel", rpm:"rust-regex+unicode-bool-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-case-devel", rpm:"rust-regex+unicode-case-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-devel", rpm:"rust-regex+unicode-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-gencat-devel", rpm:"rust-regex+unicode-gencat-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-perl-devel", rpm:"rust-regex+unicode-perl-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-script-devel", rpm:"rust-regex+unicode-script-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-segment-devel", rpm:"rust-regex+unicode-segment-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unstable-devel", rpm:"rust-regex+unstable-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+use_std-devel", rpm:"rust-regex+use_std-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex", rpm:"rust-regex~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+alloc-devel", rpm:"rust-regex-automata+alloc-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+default-devel", rpm:"rust-regex-automata+default-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+dfa-build-devel", rpm:"rust-regex-automata+dfa-build-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+dfa-devel", rpm:"rust-regex-automata+dfa-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+dfa-onepass-devel", rpm:"rust-regex-automata+dfa-onepass-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+dfa-search-devel", rpm:"rust-regex-automata+dfa-search-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+hybrid-devel", rpm:"rust-regex-automata+hybrid-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+internal-instrument-devel", rpm:"rust-regex-automata+internal-instrument-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+internal-instrument-pikevm-devel", rpm:"rust-regex-automata+internal-instrument-pikevm-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+logging-devel", rpm:"rust-regex-automata+logging-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+meta-devel", rpm:"rust-regex-automata+meta-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+nfa-backtrack-devel", rpm:"rust-regex-automata+nfa-backtrack-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+nfa-devel", rpm:"rust-regex-automata+nfa-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+nfa-pikevm-devel", rpm:"rust-regex-automata+nfa-pikevm-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+nfa-thompson-devel", rpm:"rust-regex-automata+nfa-thompson-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+perf-devel", rpm:"rust-regex-automata+perf-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+perf-inline-devel", rpm:"rust-regex-automata+perf-inline-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+perf-literal-devel", rpm:"rust-regex-automata+perf-literal-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+perf-literal-multisubstring-devel", rpm:"rust-regex-automata+perf-literal-multisubstring-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+perf-literal-substring-devel", rpm:"rust-regex-automata+perf-literal-substring-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+std-devel", rpm:"rust-regex-automata+std-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+syntax-devel", rpm:"rust-regex-automata+syntax-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-age-devel", rpm:"rust-regex-automata+unicode-age-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-bool-devel", rpm:"rust-regex-automata+unicode-bool-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-case-devel", rpm:"rust-regex-automata+unicode-case-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-devel", rpm:"rust-regex-automata+unicode-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-gencat-devel", rpm:"rust-regex-automata+unicode-gencat-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-perl-devel", rpm:"rust-regex-automata+unicode-perl-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-script-devel", rpm:"rust-regex-automata+unicode-script-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-segment-devel", rpm:"rust-regex-automata+unicode-segment-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-word-boundary-devel", rpm:"rust-regex-automata+unicode-word-boundary-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata", rpm:"rust-regex-automata~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata-devel", rpm:"rust-regex-automata-devel~0.4.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-devel", rpm:"rust-regex-devel~1.11.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign+aws-devel", rpm:"rust-reqsign+aws-devel~0.18.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign+default-context-devel", rpm:"rust-reqsign+default-context-devel~0.18.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign+default-devel", rpm:"rust-reqsign+default-devel~0.18.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign", rpm:"rust-reqsign~0.18.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-aws-v4+default-devel", rpm:"rust-reqsign-aws-v4+default-devel~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-aws-v4", rpm:"rust-reqsign-aws-v4~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-aws-v4-devel", rpm:"rust-reqsign-aws-v4-devel~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-command-execute-tokio+default-devel", rpm:"rust-reqsign-command-execute-tokio+default-devel~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-command-execute-tokio", rpm:"rust-reqsign-command-execute-tokio~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-command-execute-tokio-devel", rpm:"rust-reqsign-command-execute-tokio-devel~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-core+default-devel", rpm:"rust-reqsign-core+default-devel~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-core", rpm:"rust-reqsign-core~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-core-devel", rpm:"rust-reqsign-core-devel~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-devel", rpm:"rust-reqsign-devel~0.18.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-file-read-tokio+default-devel", rpm:"rust-reqsign-file-read-tokio+default-devel~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-file-read-tokio", rpm:"rust-reqsign-file-read-tokio~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-file-read-tokio-devel", rpm:"rust-reqsign-file-read-tokio-devel~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-http-send-reqwest+default-devel", rpm:"rust-reqsign-http-send-reqwest+default-devel~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-http-send-reqwest", rpm:"rust-reqsign-http-send-reqwest~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-http-send-reqwest-devel", rpm:"rust-reqsign-http-send-reqwest-devel~2.0.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json+alloc-devel", rpm:"rust-serde_json+alloc-devel~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json+arbitrary_precision-devel", rpm:"rust-serde_json+arbitrary_precision-devel~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json+default-devel", rpm:"rust-serde_json+default-devel~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json+float_roundtrip-devel", rpm:"rust-serde_json+float_roundtrip-devel~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json+indexmap-devel", rpm:"rust-serde_json+indexmap-devel~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json+preserve_order-devel", rpm:"rust-serde_json+preserve_order-devel~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json+raw_value-devel", rpm:"rust-serde_json+raw_value-devel~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json+std-devel", rpm:"rust-serde_json+std-devel~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json+unbounded_depth-devel", rpm:"rust-serde_json+unbounded_depth-devel~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json", rpm:"rust-serde_json~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-serde_json-devel", rpm:"rust-serde_json-devel~1.0.145~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-speedate+default-devel", rpm:"rust-speedate+default-devel~0.17.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-speedate", rpm:"rust-speedate~0.17.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-speedate-devel", rpm:"rust-speedate-devel~0.17.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+background_threads-devel", rpm:"rust-tikv-jemalloc-sys+background_threads-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+background_threads_runtime_support-devel", rpm:"rust-tikv-jemalloc-sys+background_threads_runtime_support-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+debug-devel", rpm:"rust-tikv-jemalloc-sys+debug-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+default-devel", rpm:"rust-tikv-jemalloc-sys+default-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+override_allocator_on_supported_platforms-devel", rpm:"rust-tikv-jemalloc-sys+override_allocator_on_supported_platforms-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+profiling-devel", rpm:"rust-tikv-jemalloc-sys+profiling-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+stats-devel", rpm:"rust-tikv-jemalloc-sys+stats-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+unprefixed_malloc_on_supported_platforms-devel", rpm:"rust-tikv-jemalloc-sys+unprefixed_malloc_on_supported_platforms-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys", rpm:"rust-tikv-jemalloc-sys~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys-devel", rpm:"rust-tikv-jemalloc-sys-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+alloc_trait-devel", rpm:"rust-tikv-jemallocator+alloc_trait-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+background_threads-devel", rpm:"rust-tikv-jemallocator+background_threads-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+background_threads_runtime_support-devel", rpm:"rust-tikv-jemallocator+background_threads_runtime_support-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+debug-devel", rpm:"rust-tikv-jemallocator+debug-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+default-devel", rpm:"rust-tikv-jemallocator+default-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+override_allocator_on_supported_platforms-devel", rpm:"rust-tikv-jemallocator+override_allocator_on_supported_platforms-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+profiling-devel", rpm:"rust-tikv-jemallocator+profiling-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+stats-devel", rpm:"rust-tikv-jemallocator+stats-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+unprefixed_malloc_on_supported_platforms-devel", rpm:"rust-tikv-jemallocator+unprefixed_malloc_on_supported_platforms-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator", rpm:"rust-tikv-jemallocator~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator-devel", rpm:"rust-tikv-jemallocator-devel~0.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv", rpm:"uv~0.9.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debuginfo", rpm:"uv-debuginfo~0.9.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debugsource", rpm:"uv-debugsource~0.9.5~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
