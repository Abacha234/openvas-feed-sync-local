# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0240");
  script_cve_id("CVE-2025-59375", "CVE-2025-8176");
  script_tag(name:"creation_date", value:"2025-10-20 04:11:30 +0000 (Mon, 20 Oct 2025)");
  script_version("2025-10-21T05:39:32+0000");
  script_tag(name:"last_modification", value:"2025-10-21 05:39:32 +0000 (Tue, 21 Oct 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-11 16:58:39 +0000 (Thu, 11 Sep 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0240)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0240");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0240.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0109.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34111");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34640");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/09/24/11");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the MGASA-2025-0240 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper restriction of xml entity expansion depth in libexpat.
(CVE-2024-8176) This is an extension of the fix published in
MGASA-2025-0109 that was determined by upstream to be incomplete.
Libexpat in Expat before 2.7.2 allows attackers to trigger large dynamic
memory allocations via a small document that is submitted for parsing.
(CVE-2025-59375)");

  script_tag(name:"affected", value:"'expat' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.7.3~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64expat-devel", rpm:"lib64expat-devel~2.7.3~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64expat1", rpm:"lib64expat1~2.7.3~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat-devel", rpm:"libexpat-devel~2.7.3~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.7.3~1.mga9", rls:"MAGEIA9"))) {
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
