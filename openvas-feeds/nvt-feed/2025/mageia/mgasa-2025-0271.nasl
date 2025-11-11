# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0271");
  script_cve_id("CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881");
  script_tag(name:"creation_date", value:"2025-11-10 04:13:47 +0000 (Mon, 10 Nov 2025)");
  script_version("2025-11-10T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-11-10 05:40:50 +0000 (Mon, 10 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0271)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0271");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0271.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34719");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2");
  script_xref(name:"URL", value:"https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/11/05/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opencontainers-runc' package(s) announced via the MGASA-2025-0271 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The way masked paths are implemented in runc can be exploited to cause
the host system to crash or halt (CVE-2025-31133) and a flaw in
/dev/console bind-mounts can lead to container escape (CVE-2025-52565).
Also, arbitrary write gadgets and procfs write redirects could be used
to engineer container escape and denial of service (CVE-2025-52881).");

  script_tag(name:"affected", value:"'opencontainers-runc' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"opencontainers-runc", rpm:"opencontainers-runc~1.2.8~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opencontainers-runc-devel", rpm:"opencontainers-runc-devel~1.2.8~2.1.mga9", rls:"MAGEIA9"))) {
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
