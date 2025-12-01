# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.0010159831008999");
  script_tag(name:"creation_date", value:"2025-11-17 04:10:17 +0000 (Mon, 17 Nov 2025)");
  script_version("2025-11-17T05:41:16+0000");
  script_tag(name:"last_modification", value:"2025-11-17 05:41:16 +0000 (Mon, 17 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-00e5b3d89c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-00e5b3d89c");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-00e5b3d89c");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403244");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2403245");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2406419");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2406420");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411978");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411979");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411980");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411981");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411982");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411983");
  script_xref(name:"URL", value:"https://github.com/astral-sh/ruff/releases/tag/0.14.3");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/releases/tag/0.9.6");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/releases/tag/0.9.7");
  script_xref(name:"URL", value:"https://github.com/astral-sh/uv/security/advisories/GHSA-pqhf-p39g-3x64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-uv-build, ruff, rust-get-size2, rust-get-size-derive2, rust-regex, rust-regex-automata, rust-reqsign, rust-reqsign-aws-v4, rust-reqsign-command-execute-tokio, rust-reqsign-core, rust-reqsign-file-read-tokio, rust-reqsign-http-send-reqwest, uv' package(s) announced via the FEDORA-2025-00e5b3d89c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"# uv / python-uv-build

## 0.9.7

[link moved to references]

## 0.9.6

This release contains an upgrade to Astral's fork of `async_zip`, which addresses potential sources of ZIP parsing differentials between uv and other Python packaging tooling. See [GHSA-pqhf-p39g-3x64]([link moved to references]) for additional details.

[link moved to references]

----

# ruff

## 0.14.3

[link moved to references]

----

Update `rust-get-size2`/`rust-get-size-derive2` to 0.7.1 (implement `GetSize` for `RefCell`).

----

Update `rust-reqsign` to 0.18.1 and `rust-reqsign-*` to 2.0.1.

----

Update `rust-regex` to 1.12.2 and `rust-regex-automata` to 0.4.13.");

  script_tag(name:"affected", value:"'python-uv-build, ruff, rust-get-size2, rust-get-size-derive2, rust-regex, rust-regex-automata, rust-reqsign, rust-reqsign-aws-v4, rust-reqsign-command-execute-tokio, rust-reqsign-core, rust-reqsign-file-read-tokio, rust-reqsign-http-send-reqwest, uv' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build", rpm:"python-uv-build~0.9.7~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build-debugsource", rpm:"python-uv-build-debugsource~0.9.7~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ruff", rpm:"python3-ruff~0.14.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv", rpm:"python3-uv~0.9.7~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build", rpm:"python3-uv-build~0.9.7~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build-debuginfo", rpm:"python3-uv-build-debuginfo~0.9.7~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff", rpm:"ruff~0.14.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff-debuginfo", rpm:"ruff-debuginfo~0.14.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff-debugsource", rpm:"ruff-debugsource~0.14.3~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size-derive2+default-devel", rpm:"rust-get-size-derive2+default-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size-derive2", rpm:"rust-get-size-derive2~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size-derive2-devel", rpm:"rust-get-size-derive2-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+bytes-devel", rpm:"rust-get-size2+bytes-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+chrono-devel", rpm:"rust-get-size2+chrono-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+chrono-tz-devel", rpm:"rust-get-size2+chrono-tz-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+compact-str-devel", rpm:"rust-get-size2+compact-str-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+default-devel", rpm:"rust-get-size2+default-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+derive-devel", rpm:"rust-get-size2+derive-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+get-size-derive2-devel", rpm:"rust-get-size2+get-size-derive2-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+hashbrown-devel", rpm:"rust-get-size2+hashbrown-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+indexmap-devel", rpm:"rust-get-size2+indexmap-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+smallvec-devel", rpm:"rust-get-size2+smallvec-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+thin-vec-devel", rpm:"rust-get-size2+thin-vec-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2+url-devel", rpm:"rust-get-size2+url-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2", rpm:"rust-get-size2~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-get-size2-devel", rpm:"rust-get-size2-devel~0.7.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+default-devel", rpm:"rust-regex+default-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+logging-devel", rpm:"rust-regex+logging-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+pattern-devel", rpm:"rust-regex+pattern-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-backtrack-devel", rpm:"rust-regex+perf-backtrack-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-cache-devel", rpm:"rust-regex+perf-cache-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-devel", rpm:"rust-regex+perf-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-dfa-devel", rpm:"rust-regex+perf-dfa-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-dfa-full-devel", rpm:"rust-regex+perf-dfa-full-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-inline-devel", rpm:"rust-regex+perf-inline-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-literal-devel", rpm:"rust-regex+perf-literal-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+perf-onepass-devel", rpm:"rust-regex+perf-onepass-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+std-devel", rpm:"rust-regex+std-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-age-devel", rpm:"rust-regex+unicode-age-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-bool-devel", rpm:"rust-regex+unicode-bool-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-case-devel", rpm:"rust-regex+unicode-case-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-devel", rpm:"rust-regex+unicode-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-gencat-devel", rpm:"rust-regex+unicode-gencat-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-perl-devel", rpm:"rust-regex+unicode-perl-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-script-devel", rpm:"rust-regex+unicode-script-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unicode-segment-devel", rpm:"rust-regex+unicode-segment-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+unstable-devel", rpm:"rust-regex+unstable-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex+use_std-devel", rpm:"rust-regex+use_std-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex", rpm:"rust-regex~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+alloc-devel", rpm:"rust-regex-automata+alloc-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+default-devel", rpm:"rust-regex-automata+default-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+dfa-build-devel", rpm:"rust-regex-automata+dfa-build-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+dfa-devel", rpm:"rust-regex-automata+dfa-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+dfa-onepass-devel", rpm:"rust-regex-automata+dfa-onepass-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+dfa-search-devel", rpm:"rust-regex-automata+dfa-search-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+hybrid-devel", rpm:"rust-regex-automata+hybrid-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+internal-instrument-devel", rpm:"rust-regex-automata+internal-instrument-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+internal-instrument-pikevm-devel", rpm:"rust-regex-automata+internal-instrument-pikevm-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+logging-devel", rpm:"rust-regex-automata+logging-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+meta-devel", rpm:"rust-regex-automata+meta-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+nfa-backtrack-devel", rpm:"rust-regex-automata+nfa-backtrack-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+nfa-devel", rpm:"rust-regex-automata+nfa-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+nfa-pikevm-devel", rpm:"rust-regex-automata+nfa-pikevm-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+nfa-thompson-devel", rpm:"rust-regex-automata+nfa-thompson-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+perf-devel", rpm:"rust-regex-automata+perf-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+perf-inline-devel", rpm:"rust-regex-automata+perf-inline-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+perf-literal-devel", rpm:"rust-regex-automata+perf-literal-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+perf-literal-multisubstring-devel", rpm:"rust-regex-automata+perf-literal-multisubstring-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+perf-literal-substring-devel", rpm:"rust-regex-automata+perf-literal-substring-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+std-devel", rpm:"rust-regex-automata+std-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+syntax-devel", rpm:"rust-regex-automata+syntax-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-age-devel", rpm:"rust-regex-automata+unicode-age-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-bool-devel", rpm:"rust-regex-automata+unicode-bool-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-case-devel", rpm:"rust-regex-automata+unicode-case-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-devel", rpm:"rust-regex-automata+unicode-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-gencat-devel", rpm:"rust-regex-automata+unicode-gencat-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-perl-devel", rpm:"rust-regex-automata+unicode-perl-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-script-devel", rpm:"rust-regex-automata+unicode-script-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-segment-devel", rpm:"rust-regex-automata+unicode-segment-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata+unicode-word-boundary-devel", rpm:"rust-regex-automata+unicode-word-boundary-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata", rpm:"rust-regex-automata~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-automata-devel", rpm:"rust-regex-automata-devel~0.4.13~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-regex-devel", rpm:"rust-regex-devel~1.12.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign+aws-devel", rpm:"rust-reqsign+aws-devel~0.18.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign+default-context-devel", rpm:"rust-reqsign+default-context-devel~0.18.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign+default-devel", rpm:"rust-reqsign+default-devel~0.18.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign", rpm:"rust-reqsign~0.18.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-aws-v4+default-devel", rpm:"rust-reqsign-aws-v4+default-devel~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-aws-v4", rpm:"rust-reqsign-aws-v4~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-aws-v4-devel", rpm:"rust-reqsign-aws-v4-devel~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-command-execute-tokio+default-devel", rpm:"rust-reqsign-command-execute-tokio+default-devel~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-command-execute-tokio", rpm:"rust-reqsign-command-execute-tokio~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-command-execute-tokio-devel", rpm:"rust-reqsign-command-execute-tokio-devel~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-core+default-devel", rpm:"rust-reqsign-core+default-devel~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-core", rpm:"rust-reqsign-core~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-core-devel", rpm:"rust-reqsign-core-devel~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-devel", rpm:"rust-reqsign-devel~0.18.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-file-read-tokio+default-devel", rpm:"rust-reqsign-file-read-tokio+default-devel~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-file-read-tokio", rpm:"rust-reqsign-file-read-tokio~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-file-read-tokio-devel", rpm:"rust-reqsign-file-read-tokio-devel~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-http-send-reqwest+default-devel", rpm:"rust-reqsign-http-send-reqwest+default-devel~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-http-send-reqwest", rpm:"rust-reqsign-http-send-reqwest~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-reqsign-http-send-reqwest-devel", rpm:"rust-reqsign-http-send-reqwest-devel~2.0.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv", rpm:"uv~0.9.7~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debuginfo", rpm:"uv-debuginfo~0.9.7~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debugsource", rpm:"uv-debugsource~0.9.7~2.fc41", rls:"FC41"))) {
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
