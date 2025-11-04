# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.4397098102102510197");
  script_cve_id("CVE-2025-62518");
  script_tag(name:"creation_date", value:"2025-11-03 04:10:08 +0000 (Mon, 03 Nov 2025)");
  script_version("2025-11-03T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-03 05:40:08 +0000 (Mon, 03 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-43a0bff5ea)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-43a0bff5ea");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-43a0bff5ea");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2360699");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402441");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402442");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402443");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402881");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2402923");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2405471");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2405472");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2406135");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-j5gw-2vrg-8fgx");
  script_xref(name:"URL", value:"https://github.com/astral-sh/ruff/blob/0.14.2/CHANGELOG.md");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/blob/0.9.5/CHANGELOG.md");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openapi-python-client, python-uv-build, ruff, rust-astral-tokio-tar, rust-attribute-derive, rust-attribute-derive-macro, rust-backon, rust-collection_literals, rust-get-size2, rust-get-size-derive2, rust-interpolator, rust-manyhow, rust-manyhow-macros, rust-proc-macro-utils, rust-quote-use, rust-quote-use-macros, rust-reqsign, rust-reqsign-aws-v4, rust-reqsign-command-execute-tokio, rust-reqsign-core, rust-reqsign-file-read-tokio, rust-reqsign-http-send-reqwest, rust-tikv-jemalloc-sys, rust-tikv-jemallocator, uv' package(s) announced via the FEDORA-2025-43a0bff5ea advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## uv 0.9.5

[link moved to references]

Since uv was built with astral-tokio-tar 0.5.6, this is a security fix for CVE-2025-62518.

----

## ruff 0.14.2

[link moved to references]

----

## rust-astral-tokio-tar 0.5.6

* Fixed a parser desynchronization vulnerability when reading tar archives that
 contain mismatched size information in PAX/ustar headers.

 This vulnerability is being tracked as [GHSA-j5gw-2vrg-8fgx]([link moved to references])
 and CVE-2025-62518.

----

- Initial package for `python-uv-build` in Fedora 42
- Initial packages for a number of new dependencies for `ruff` and `uv`.
- Update `rust-tikv-jemallocator` and `rust-tikv-jemalloc-sys` to 0.6.1.
- Patch `openapi-python-client` to allow `ruff` 0.14");

  script_tag(name:"affected", value:"'openapi-python-client, python-uv-build, ruff, rust-astral-tokio-tar, rust-attribute-derive, rust-attribute-derive-macro, rust-backon, rust-collection_literals, rust-get-size2, rust-get-size-derive2, rust-interpolator, rust-manyhow, rust-manyhow-macros, rust-proc-macro-utils, rust-quote-use, rust-quote-use-macros, rust-reqsign, rust-reqsign-aws-v4, rust-reqsign-command-execute-tokio, rust-reqsign-core, rust-reqsign-file-read-tokio, rust-reqsign-http-send-reqwest, rust-tikv-jemalloc-sys, rust-tikv-jemallocator, uv' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"openapi-python-client", rpm:"openapi-python-client~0.24.3~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build", rpm:"python-uv-build~0.9.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build-debugsource", rpm:"python-uv-build-debugsource~0.9.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ruff", rpm:"python3-ruff~0.14.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv", rpm:"python3-uv~0.9.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build", rpm:"python3-uv-build~0.9.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build-debuginfo", rpm:"python3-uv-build-debuginfo~0.9.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff", rpm:"ruff~0.14.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff-debuginfo", rpm:"ruff-debuginfo~0.14.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff-debugsource", rpm:"ruff-debugsource~0.14.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar+default-devel", rpm:"rust-astral-tokio-tar+default-devel~0.5.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar+xattr-devel", rpm:"rust-astral-tokio-tar+xattr-devel~0.5.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar", rpm:"rust-astral-tokio-tar~0.5.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-astral-tokio-tar-devel", rpm:"rust-astral-tokio-tar-devel~0.5.6~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive+default-devel", rpm:"rust-attribute-derive+default-devel~0.10.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive+syn-full-devel", rpm:"rust-attribute-derive+syn-full-devel~0.10.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive", rpm:"rust-attribute-derive~0.10.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive-devel", rpm:"rust-attribute-derive-devel~0.10.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive-macro+default-devel", rpm:"rust-attribute-derive-macro+default-devel~0.10.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive-macro", rpm:"rust-attribute-derive-macro~0.10.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-attribute-derive-macro-devel", rpm:"rust-attribute-derive-macro-devel~0.10.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-backon+default-devel", rpm:"rust-backon+default-devel~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-backon+futures-timer-devel", rpm:"rust-backon+futures-timer-devel~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-backon+futures-timer-sleep-devel", rpm:"rust-backon+futures-timer-sleep-devel~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-backon+std-blocking-sleep-devel", rpm:"rust-backon+std-blocking-sleep-devel~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-backon+std-devel", rpm:"rust-backon+std-devel~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-backon+tokio-devel", rpm:"rust-backon+tokio-devel~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-backon+tokio-sleep-devel", rpm:"rust-backon+tokio-sleep-devel~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-backon", rpm:"rust-backon~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-backon-devel", rpm:"rust-backon-devel~1.6.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-collection_literals+default-devel", rpm:"rust-collection_literals+default-devel~1.0.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-collection_literals", rpm:"rust-collection_literals~1.0.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-collection_literals-devel", rpm:"rust-collection_literals-devel~1.0.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size-derive2+default-devel", rpm:"rust-get-size-derive2+default-devel~0.7.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size-derive2", rpm:"rust-get-size-derive2~0.7.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size-derive2-devel", rpm:"rust-get-size-derive2-devel~0.7.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+bytes-devel", rpm:"rust-get-size2+bytes-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+chrono-devel", rpm:"rust-get-size2+chrono-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+chrono-tz-devel", rpm:"rust-get-size2+chrono-tz-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+compact-str-devel", rpm:"rust-get-size2+compact-str-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+default-devel", rpm:"rust-get-size2+default-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+derive-devel", rpm:"rust-get-size2+derive-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+get-size-derive2-devel", rpm:"rust-get-size2+get-size-derive2-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+hashbrown-devel", rpm:"rust-get-size2+hashbrown-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+indexmap-devel", rpm:"rust-get-size2+indexmap-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+smallvec-devel", rpm:"rust-get-size2+smallvec-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+thin-vec-devel", rpm:"rust-get-size2+thin-vec-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+url-devel", rpm:"rust-get-size2+url-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2", rpm:"rust-get-size2~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2-devel", rpm:"rust-get-size2-devel~0.7.0~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator+debug-devel", rpm:"rust-interpolator+debug-devel~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator+default-devel", rpm:"rust-interpolator+default-devel~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator+iter-devel", rpm:"rust-interpolator+iter-devel~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator+number-devel", rpm:"rust-interpolator+number-devel~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator+pointer-devel", rpm:"rust-interpolator+pointer-devel~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator", rpm:"rust-interpolator~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-interpolator-devel", rpm:"rust-interpolator-devel~0.5.0~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+darling-devel", rpm:"rust-manyhow+darling-devel~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+darling_core-devel", rpm:"rust-manyhow+darling_core-devel~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+default-devel", rpm:"rust-manyhow+default-devel~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+macros-devel", rpm:"rust-manyhow+macros-devel~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+syn-devel", rpm:"rust-manyhow+syn-devel~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+syn1-devel", rpm:"rust-manyhow+syn1-devel~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow+syn2-devel", rpm:"rust-manyhow+syn2-devel~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow", rpm:"rust-manyhow~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow-devel", rpm:"rust-manyhow-devel~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow-macros+default-devel", rpm:"rust-manyhow-macros+default-devel~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow-macros", rpm:"rust-manyhow-macros~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-manyhow-macros-devel", rpm:"rust-manyhow-macros-devel~0.11.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+default-devel", rpm:"rust-proc-macro-utils+default-devel~0.10.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+parser-devel", rpm:"rust-proc-macro-utils+parser-devel~0.10.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+proc-macro-devel", rpm:"rust-proc-macro-utils+proc-macro-devel~0.10.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+proc-macro2-devel", rpm:"rust-proc-macro-utils+proc-macro2-devel~0.10.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+quote-devel", rpm:"rust-proc-macro-utils+quote-devel~0.10.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils+smallvec-devel", rpm:"rust-proc-macro-utils+smallvec-devel~0.10.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils", rpm:"rust-proc-macro-utils~0.10.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-proc-macro-utils-devel", rpm:"rust-proc-macro-utils-devel~0.10.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use+default-devel", rpm:"rust-quote-use+default-devel~0.8.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use+syn-devel", rpm:"rust-quote-use+syn-devel~0.8.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use", rpm:"rust-quote-use~0.8.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use-devel", rpm:"rust-quote-use-devel~0.8.4~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use-macros+default-devel", rpm:"rust-quote-use-macros+default-devel~0.8.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use-macros", rpm:"rust-quote-use-macros~0.8.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-quote-use-macros-devel", rpm:"rust-quote-use-macros-devel~0.8.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign+aws-devel", rpm:"rust-reqsign+aws-devel~0.18.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign+default-context-devel", rpm:"rust-reqsign+default-context-devel~0.18.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign+default-devel", rpm:"rust-reqsign+default-devel~0.18.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign", rpm:"rust-reqsign~0.18.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-aws-v4+default-devel", rpm:"rust-reqsign-aws-v4+default-devel~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-aws-v4", rpm:"rust-reqsign-aws-v4~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-aws-v4-devel", rpm:"rust-reqsign-aws-v4-devel~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-command-execute-tokio+default-devel", rpm:"rust-reqsign-command-execute-tokio+default-devel~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-command-execute-tokio", rpm:"rust-reqsign-command-execute-tokio~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-command-execute-tokio-devel", rpm:"rust-reqsign-command-execute-tokio-devel~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-core+default-devel", rpm:"rust-reqsign-core+default-devel~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-core", rpm:"rust-reqsign-core~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-core-devel", rpm:"rust-reqsign-core-devel~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-devel", rpm:"rust-reqsign-devel~0.18.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-file-read-tokio+default-devel", rpm:"rust-reqsign-file-read-tokio+default-devel~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-file-read-tokio", rpm:"rust-reqsign-file-read-tokio~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-file-read-tokio-devel", rpm:"rust-reqsign-file-read-tokio-devel~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-http-send-reqwest+default-devel", rpm:"rust-reqsign-http-send-reqwest+default-devel~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-http-send-reqwest", rpm:"rust-reqsign-http-send-reqwest~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-http-send-reqwest-devel", rpm:"rust-reqsign-http-send-reqwest-devel~2.0.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+background_threads-devel", rpm:"rust-tikv-jemalloc-sys+background_threads-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+background_threads_runtime_support-devel", rpm:"rust-tikv-jemalloc-sys+background_threads_runtime_support-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+debug-devel", rpm:"rust-tikv-jemalloc-sys+debug-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+default-devel", rpm:"rust-tikv-jemalloc-sys+default-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+override_allocator_on_supported_platforms-devel", rpm:"rust-tikv-jemalloc-sys+override_allocator_on_supported_platforms-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+profiling-devel", rpm:"rust-tikv-jemalloc-sys+profiling-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+stats-devel", rpm:"rust-tikv-jemalloc-sys+stats-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys+unprefixed_malloc_on_supported_platforms-devel", rpm:"rust-tikv-jemalloc-sys+unprefixed_malloc_on_supported_platforms-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys", rpm:"rust-tikv-jemalloc-sys~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemalloc-sys-devel", rpm:"rust-tikv-jemalloc-sys-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+alloc_trait-devel", rpm:"rust-tikv-jemallocator+alloc_trait-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+background_threads-devel", rpm:"rust-tikv-jemallocator+background_threads-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+background_threads_runtime_support-devel", rpm:"rust-tikv-jemallocator+background_threads_runtime_support-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+debug-devel", rpm:"rust-tikv-jemallocator+debug-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+default-devel", rpm:"rust-tikv-jemallocator+default-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+override_allocator_on_supported_platforms-devel", rpm:"rust-tikv-jemallocator+override_allocator_on_supported_platforms-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+profiling-devel", rpm:"rust-tikv-jemallocator+profiling-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+stats-devel", rpm:"rust-tikv-jemallocator+stats-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator+unprefixed_malloc_on_supported_platforms-devel", rpm:"rust-tikv-jemallocator+unprefixed_malloc_on_supported_platforms-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator", rpm:"rust-tikv-jemallocator~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-tikv-jemallocator-devel", rpm:"rust-tikv-jemallocator-devel~0.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv", rpm:"uv~0.9.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debuginfo", rpm:"uv-debuginfo~0.9.5~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debugsource", rpm:"uv-debugsource~0.9.5~1.fc41", rls:"FC41"))) {
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
