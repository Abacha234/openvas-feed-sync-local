# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0237");
  script_cve_id("CVE-2025-41244");
  script_tag(name:"creation_date", value:"2025-10-13 04:08:44 +0000 (Mon, 13 Oct 2025)");
  script_version("2025-10-31T15:42:05+0000");
  script_tag(name:"last_modification", value:"2025-10-31 15:42:05 +0000 (Fri, 31 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0237)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0237");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0237.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34641");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/09/29/10");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-vm-tools' package(s) announced via the MGASA-2025-0237 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that open-vm-tools contains a local privilege
escalation vulnerability. A malicious actor with non-administrative
privileges on a guest VM may exploit this vulnerability to escalate
privileges to root on the same VM (CVE-2025-41244).");

  script_tag(name:"affected", value:"'open-vm-tools' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~12.3.5~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~12.3.5~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-devel", rpm:"open-vm-tools-devel~12.3.5~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-salt-minion", rpm:"open-vm-tools-salt-minion~12.3.5~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-sdmp", rpm:"open-vm-tools-sdmp~12.3.5~2.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-test", rpm:"open-vm-tools-test~12.3.5~2.2.mga9", rls:"MAGEIA9"))) {
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
