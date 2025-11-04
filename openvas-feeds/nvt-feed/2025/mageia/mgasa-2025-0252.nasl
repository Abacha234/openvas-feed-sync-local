# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0252");
  script_cve_id("CVE-2024-13978", "CVE-2025-8176", "CVE-2025-8177", "CVE-2025-8534", "CVE-2025-8961", "CVE-2025-9165", "CVE-2025-9900");
  script_tag(name:"creation_date", value:"2025-11-03 04:13:32 +0000 (Mon, 03 Nov 2025)");
  script_version("2025-11-03T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-03 05:40:08 +0000 (Mon, 03 Nov 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-23 17:15:38 +0000 (Tue, 23 Sep 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0252)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0252");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0252.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34704");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2025/msg00189.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff' package(s) announced via the MGASA-2025-0252 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LibTIFF fax2ps tiff2pdf.c t2p_read_tiff_init null pointer dereference.
(CVE-2024-13978)
LibTIFF tiffmedian.c get_histogram use after free. (CVE-2025-8176)
LibTIFF thumbnail.c setrow buffer overflow. (CVE-2025-8177)
libtiff tiff2ps tiff2ps.c PS_Lvl2page null pointer dereference.
(CVE-2025-8534)
LibTIFF tiffcrop tiffcrop.c main memory corruption. (CVE-2025-8961)
LibTIFF tiffcmp tiffcmp.c InitCCITTFax3 memory leak. (CVE-2025-9165)
Libtiff: libtiff write-what-where. (CVE-2025-9900)");

  script_tag(name:"affected", value:"'libtiff' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-devel", rpm:"lib64tiff-devel~4.5.1~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-static-devel", rpm:"lib64tiff-static-devel~4.5.1~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff6", rpm:"lib64tiff6~4.5.1~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.5.1~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.5.1~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~4.5.1~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static-devel", rpm:"libtiff-static-devel~4.5.1~1.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff6", rpm:"libtiff6~4.5.1~1.6.mga9", rls:"MAGEIA9"))) {
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
