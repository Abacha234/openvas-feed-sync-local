# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0269");
  script_cve_id("CVE-2025-49794", "CVE-2025-49795", "CVE-2025-49796", "CVE-2025-6021", "CVE-2025-6170", "CVE-2025-7424", "CVE-2025-7425");
  script_tag(name:"creation_date", value:"2025-11-10 04:13:47 +0000 (Mon, 10 Nov 2025)");
  script_version("2025-11-10T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-11-10 05:40:50 +0000 (Mon, 10 Nov 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-16 16:15:19 +0000 (Mon, 16 Jun 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0269)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0269");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0269.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34378");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/06/16/6");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/11/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2, libxslt' package(s) announced via the MGASA-2025-0269 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Heap use after free (UAF) leads to Denial of service (DoS).
(CVE-2025-49794)
Null pointer dereference leads to Denial of service (DoS).
(CVE-2025-49795)
Type confusion leads to Denial of service (DoS). (CVE-2025-49796)
Integer Overflow Leading to Buffer Overflow in xmlBuildQName().
(CVE-2025-6021)
Stack-based Buffer Overflow in xmllint Shell. (CVE-2025-6170)
Type confusion in xmlNode.psvi between stylesheet and source nodes.
(CVE-2025-7424)
Heap-use-after-free in xmlFreeID caused by `atype` corruption.
(CVE-2025-7425)");

  script_tag(name:"affected", value:"'libxml2, libxslt' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64exslt0", rpm:"lib64exslt0~1.1.38~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xml2-devel", rpm:"lib64xml2-devel~2.10.4~1.8.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xml2_2", rpm:"lib64xml2_2~2.10.4~1.8.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xslt-devel", rpm:"lib64xslt-devel~1.1.38~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xslt1", rpm:"lib64xslt1~1.1.38~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexslt0", rpm:"libexslt0~1.1.38~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.10.4~1.8.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.10.4~1.8.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python3", rpm:"libxml2-python3~2.10.4~1.8.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-utils", rpm:"libxml2-utils~2.10.4~1.8.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2_2", rpm:"libxml2_2~2.10.4~1.8.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.38~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.38~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt1", rpm:"libxslt1~1.1.38~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxslt", rpm:"python3-libxslt~1.1.38~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xsltproc", rpm:"xsltproc~1.1.38~1.2.mga9", rls:"MAGEIA9"))) {
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
