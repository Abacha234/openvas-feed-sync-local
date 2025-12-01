# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0281");
  script_cve_id("CVE-2025-50181");
  script_tag(name:"creation_date", value:"2025-11-13 04:11:10 +0000 (Thu, 13 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-18 13:51:10 +0000 (Thu, 18 Sep 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0281)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0281");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0281.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34401");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7599-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7599-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pip, python-urllib3' package(s) announced via the MGASA-2025-0281 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Urllib3 redirects are not disabled when retries are disabled on
PoolManager instantiation. (CVE-2025-50181)");

  script_tag(name:"affected", value:"'python-pip, python-urllib3' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pip", rpm:"python-pip~23.0.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pip-doc", rpm:"python-pip-doc~23.0.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pip-wheel", rpm:"python-pip-wheel~23.0.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-urllib3", rpm:"python-urllib3~1.26.20~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pip", rpm:"python3-pip~23.0.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3+brotli", rpm:"python3-urllib3+brotli~1.26.20~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3+socks", rpm:"python3-urllib3+socks~1.26.20~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3", rpm:"python3-urllib3~1.26.20~1.1.mga9", rls:"MAGEIA9"))) {
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
