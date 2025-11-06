# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0257");
  script_cve_id("CVE-2025-48174", "CVE-2025-48175");
  script_tag(name:"creation_date", value:"2025-11-05 04:10:18 +0000 (Wed, 05 Nov 2025)");
  script_version("2025-11-05T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-11-05 05:40:07 +0000 (Wed, 05 Nov 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-04 20:02:37 +0000 (Wed, 04 Jun 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0257)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0257");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0257.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34336");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2025/msg00094.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libavif' package(s) announced via the MGASA-2025-0257 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In libavif before 1.3.0, makeRoom in stream.c has an integer overflow
and resultant buffer overflow in stream->offset+size. (CVE-2025-48174)
In libavif before 1.3.0, avifImageRGBToYUV in reformat.c has integer
overflows in multiplications involving rgbRowBytes, yRowBytes,
uRowBytes, and vRowBytes. (CVE-2025-48175)");

  script_tag(name:"affected", value:"'libavif' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"avif-pixbuf-loader", rpm:"avif-pixbuf-loader~0.11.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avif-devel", rpm:"lib64avif-devel~0.11.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avif15", rpm:"lib64avif15~0.11.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavif", rpm:"libavif~0.11.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavif-devel", rpm:"libavif-devel~0.11.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavif-tools", rpm:"libavif-tools~0.11.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavif15", rpm:"libavif15~0.11.1~1.1.mga9", rls:"MAGEIA9"))) {
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
