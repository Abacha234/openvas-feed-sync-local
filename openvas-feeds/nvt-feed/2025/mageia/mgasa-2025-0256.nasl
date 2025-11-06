# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0256");
  script_cve_id("CVE-2025-47912", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58186", "CVE-2025-58187", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61724", "CVE-2025-61725");
  script_tag(name:"creation_date", value:"2025-11-05 04:10:18 +0000 (Wed, 05 Nov 2025)");
  script_version("2025-11-05T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-11-05 05:40:07 +0000 (Wed, 05 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0256)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0256");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0256.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34651");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/10/08/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2025-0256 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Insufficient validation of bracketed IPv6 hostnames in net/url.
(CVE-2025-47912)
Unbounded allocation when parsing GNU sparse map in archive/tar.
(CVE-2025-58183)
Parsing DER payload can cause memory exhaustion in encoding/asn1.
(CVE-2025-58185)
Lack of limit when parsing cookies can cause memory exhaustion in
net/http. (CVE-2025-58186)
Quadratic complexity when checking name constraints in crypto/x509.
(CVE-2025-58187)
Panic when validating certificates with DSA public keys in crypto/x509.
(CVE-2025-58188)
ALPN negotiation error contains attacker controlled information in
crypto/tls. (CVE-2025-58189)
Quadratic complexity when parsing some invalid inputs in encoding/pem.
(CVE-2025-61723)
Excessive CPU consumption in Reader.ReadResponse in net/textproto.
(CVE-2025-61724)
Excessive CPU consumption in ParseAddress in net/mail. (CVE-2025-61725)
These packages fix the issues for the compiler only, applications using the
functions still need to be rebuilt.");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.24.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.24.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.24.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.24.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.24.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.24.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.24.9~1.mga9", rls:"MAGEIA9"))) {
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
