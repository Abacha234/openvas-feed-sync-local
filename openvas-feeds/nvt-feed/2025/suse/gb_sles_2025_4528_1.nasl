# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4528.1");
  script_cve_id("CVE-2025-14174", "CVE-2025-43501", "CVE-2025-43529", "CVE-2025-43531", "CVE-2025-43535", "CVE-2025-43536", "CVE-2025-43541");
  script_tag(name:"creation_date", value:"2025-12-29 04:32:26 +0000 (Mon, 29 Dec 2025)");
  script_version("2026-01-01T05:49:19+0000");
  script_tag(name:"last_modification", value:"2026-01-01 05:49:19 +0000 (Thu, 01 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4528-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4528-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254528-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255497");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023654.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2025:4528-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

Update to version 2.50.4.

Security issues fixed:

- CVE-2025-14174: processing maliciously crafted web content may lead to memory corruption due to improper validation
 (bsc#1255497).
- CVE-2025-43501: processing maliciously crafted web content may lead to an unexpected process crash due to a buffer
 overflow issue (bsc#1255194).
- CVE-2025-43529: processing maliciously crafted web content may lead to arbitrary code execution due to a
 use-after-free issue (bsc#1255198).
- CVE-2025-43531: processing maliciously crafted web content may lead to an unexpected process crash due to a race
 condition (bsc#1255183).
- CVE-2025-43535: processing maliciously crafted web content may lead to an unexpected process crash due to improper
 memory handling (bsc#1255195).
- CVE-2025-43536: processing maliciously crafted web content may lead to an unexpected process crash due to a
 use-after-free issue (bsc#1255200).
- CVE-2025-43541: processing maliciously crafted web content may lead to an unexpected process crash due to type
 confusion (bsc#1255191).

Other updates and bugfixes:

- Correctly handle the program name passed to the sleep disabler.
- Ensure GStreamer is initialized before using the Quirks.
- Fix several crashes and rendering issues.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Server 12-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.50.4~4.51.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.50.4~4.51.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.50.4~4.51.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.50.4~4.51.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.50.4~4.51.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.50.4~4.51.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.50.4~4.51.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.50.4~4.51.1", rls:"SLES12.0SP5"))) {
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
