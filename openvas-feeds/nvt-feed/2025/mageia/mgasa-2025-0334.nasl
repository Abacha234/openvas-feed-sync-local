# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0334");
  script_cve_id("CVE-2025-46727", "CVE-2025-49007", "CVE-2025-59830", "CVE-2025-61770", "CVE-2025-61771", "CVE-2025-61772", "CVE-2025-61780", "CVE-2025-61919");
  script_tag(name:"creation_date", value:"2025-12-30 04:22:16 +0000 (Tue, 30 Dec 2025)");
  script_version("2026-01-01T05:49:19+0000");
  script_tag(name:"last_modification", value:"2026-01-01 05:49:19 +0000 (Thu, 01 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-17 19:44:47 +0000 (Tue, 17 Jun 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0334)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0334");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0334.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34755");
  script_xref(name:"URL", value:"https://rack.github.io/rack/3.2/CHANGELOG_md.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby-rack' package(s) announced via the MGASA-2025-0334 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Unbounded-Parameter DoS in Rack::QueryParser. (CVE-2025-46727)
ReDoS Vulnerability in Rack::Multipart handle_mime_head.
(CVE-2025-49007)
Rack QueryParser has an unsafe default allowing params_limit bypass via
semicolon-separated parameters. (CVE-2025-59830)
Rack's unbounded multipart preamble buffering enables DoS (memory
exhaustion). (CVE-2025-61770)
Rack's multipart parser buffers large non-file fields entirely in
memory, enabling DoS (memory exhaustion). (CVE-2025-61771)
Rack's multipart parser buffers unbounded per-part headers, enabling DoS
(memory exhaustion). (CVE-2025-61772)
Rack is vulnerable to a memory-exhaustion DoS through unbounded
URL-encoded body parsing. (CVE-2025-61919)
Rack has Possible Information Disclosure Vulnerability. (CVE-2025-61780)");

  script_tag(name:"affected", value:"'ruby-rack' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"ruby-rack", rpm:"ruby-rack~2.2.21~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rack-doc", rpm:"ruby-rack-doc~2.2.21~1.mga9", rls:"MAGEIA9"))) {
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
