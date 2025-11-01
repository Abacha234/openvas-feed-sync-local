# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0241");
  script_cve_id("CVE-2025-9230", "CVE-2025-9232");
  script_tag(name:"creation_date", value:"2025-10-21 04:09:19 +0000 (Tue, 21 Oct 2025)");
  script_version("2025-10-22T05:39:59+0000");
  script_tag(name:"last_modification", value:"2025-10-22 05:39:59 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0241)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0241");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0241.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34674");
  script_xref(name:"URL", value:"https://openssl-library.org/news/vulnerabilities/#CVE-2025-9230");
  script_xref(name:"URL", value:"https://openssl-library.org/news/vulnerabilities/#CVE-2025-9232");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quictls' package(s) announced via the MGASA-2025-0241 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues and miscellaneous minor bug fixes.
Fix Out-of-bounds read & write in RFC 3211 KEK Unwrap. (CVE-2025-9230)
Fix Out-of-bounds read in HTTP client no_proxy handling. (CVE-2025-9232)");

  script_tag(name:"affected", value:"'quictls' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64quictls-devel", rpm:"lib64quictls-devel~3.0.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quictls-static-devel", rpm:"lib64quictls-static-devel~3.0.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quictls81.3", rpm:"lib64quictls81.3~3.0.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquictls-devel", rpm:"libquictls-devel~3.0.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquictls-static-devel", rpm:"libquictls-static-devel~3.0.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquictls81.3", rpm:"libquictls81.3~3.0.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quictls", rpm:"quictls~3.0.18~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quictls-perl", rpm:"quictls-perl~3.0.18~1.mga9", rls:"MAGEIA9"))) {
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
