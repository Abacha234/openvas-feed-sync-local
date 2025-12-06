# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0321");
  script_cve_id("CVE-2018-15853", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15863");
  script_tag(name:"creation_date", value:"2025-12-05 04:14:31 +0000 (Fri, 05 Dec 2025)");
  script_version("2025-12-05T05:44:55+0000");
  script_tag(name:"last_modification", value:"2025-12-05 05:44:55 +0000 (Fri, 05 Dec 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-23 16:47:02 +0000 (Tue, 23 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2025-0321)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0321");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0321.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34796");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/12/03/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xkbcomp' package(s) announced via the MGASA-2025-0321 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Endless recursion in xkbcomp/expr.c resulting in a crash.
(CVE-2018-15853)
NULL pointer dereference when parsing invalid atoms in ExprResolveLhs
resulting in a crash. (CVE-2018-15859)
NULL pointer dereference in ExprResolveLhs resulting in a crash.
(CVE-2018-15861)
NULL pointer dereference in ResolveStateAndPredicate resulting in a
crash. (CVE-2018-15863)");

  script_tag(name:"affected", value:"'xkbcomp' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"xkbcomp", rpm:"xkbcomp~1.4.6~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xkbcomp-devel", rpm:"xkbcomp-devel~1.4.6~1.1.mga9", rls:"MAGEIA9"))) {
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
