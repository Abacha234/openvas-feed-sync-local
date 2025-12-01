# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0303");
  script_cve_id("CVE-2024-42472");
  script_tag(name:"creation_date", value:"2025-11-19 04:10:01 +0000 (Wed, 19 Nov 2025)");
  script_version("2025-11-19T05:40:23+0000");
  script_tag(name:"last_modification", value:"2025-11-19 05:40:23 +0000 (Wed, 19 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0303)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0303");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0303.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33510");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2024/08/14/6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bubblewrap, flatpak' package(s) announced via the MGASA-2025-0303 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Flatpak may allow access to files outside sandbox for certain apps.
(CVE-2024-42472).");

  script_tag(name:"affected", value:"'bubblewrap, flatpak' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"bubblewrap", rpm:"bubblewrap~0.7.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.14.10~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-tests", rpm:"flatpak-tests~1.14.10~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak-devel", rpm:"lib64flatpak-devel~1.14.10~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak-gir1.0", rpm:"lib64flatpak-gir1.0~1.14.10~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak0", rpm:"lib64flatpak0~1.14.10~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak-devel", rpm:"libflatpak-devel~1.14.10~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak-gir1.0", rpm:"libflatpak-gir1.0~1.14.10~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0", rpm:"libflatpak0~1.14.10~1.mga9", rls:"MAGEIA9"))) {
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
