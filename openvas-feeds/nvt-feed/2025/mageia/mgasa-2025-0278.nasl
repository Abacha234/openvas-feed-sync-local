# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0278");
  script_cve_id("CVE-2011-10007");
  script_tag(name:"creation_date", value:"2025-11-13 04:11:10 +0000 (Thu, 13 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0278)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0278");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0278.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34352");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/5IU76LFGXLXKYPWUGOA3WJD5MKZXGVV6/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/06/05/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-File-Find-Rule' package(s) announced via the MGASA-2025-0278 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"File::Find::Rule through 0.34 for Perl is vulnerable to Arbitrary Code
Execution when `grep()` encounters a crafted file name. (CVE-2011-10007)");

  script_tag(name:"affected", value:"'perl-File-Find-Rule' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-File-Find-Rule", rpm:"perl-File-Find-Rule~0.340.0~5.1.mga9", rls:"MAGEIA9"))) {
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
