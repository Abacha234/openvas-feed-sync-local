# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0272");
  script_cve_id("CVE-2025-62291");
  script_tag(name:"creation_date", value:"2025-11-11 04:11:04 +0000 (Tue, 11 Nov 2025)");
  script_version("2025-11-11T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-11 05:40:18 +0000 (Tue, 11 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0272)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0272");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0272.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34705");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/QVE27CU4U3DGHAD4EVF75YM3RK423ZQS/");
  script_xref(name:"URL", value:"https://www.strongswan.org/blog/2025/10/27/strongswan-vulnerability-(cve-2025-62291).html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan' package(s) announced via the MGASA-2025-0272 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer Overflow When Handling EAP-MSCHAPv2 Failure Requests.
(CVE-2025-62291)");

  script_tag(name:"affected", value:"'strongswan' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64strongswan0", rpm:"lib64strongswan0~5.9.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libstrongswan0", rpm:"libstrongswan0~5.9.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~5.9.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-charon-nm", rpm:"strongswan-charon-nm~5.9.14~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-tnc-imcvs", rpm:"strongswan-tnc-imcvs~5.9.14~1.1.mga9", rls:"MAGEIA9"))) {
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
