# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0316");
  script_cve_id("CVE-2025-43961", "CVE-2025-43962", "CVE-2025-43963", "CVE-2025-43964");
  script_tag(name:"creation_date", value:"2025-12-05 04:14:31 +0000 (Fri, 05 Dec 2025)");
  script_version("2025-12-05T05:44:55+0000");
  script_tag(name:"last_modification", value:"2025-12-05 05:44:55 +0000 (Fri, 05 Dec 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-08 16:54:54 +0000 (Thu, 08 May 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0316)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0316");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0316.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34221");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/3I3BWKSTHKFJDS7ZRYZSMCPXZLSPJKIW/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/UMNI4GAUYVWHWJ2MPCIEMWUBTIM32E2H/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YDAIVZ4BSSDOYXE25CJ6Z7KXPOF4A6GL/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'darktable, digikam, libraw' package(s) announced via the MGASA-2025-0316 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In LibRaw before 0.21.4, metadata/tiff.cpp has an out-of-bounds read in
the Fujifilm 0xf00c tag parser. (CVE-2025-43961)
In LibRaw before 0.21.4, phase_one_correct in decoders/load_mfbacks.cpp
has out-of-bounds reads for tag 0x412 processing, related to large w0 or
w1 values or the frac and mult calculations. (CVE-2025-43962)
In LibRaw before 0.21.4, phase_one_correct in decoders/load_mfbacks.cpp
allows out-of-buffer access because split_col and split_row values are
not checked in 0x041f tag processing. (CVE-2025-43963)
In LibRaw before 0.21.4, tag 0x412 processing in phase_one_correct in
decoders/load_mfbacks.cpp does not enforce minimum w0 and w1 values.
(CVE-2025-43964)");

  script_tag(name:"affected", value:"'darktable, digikam, libraw' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"darktable", rpm:"darktable~4.6.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"darktable-tools-basecurve", rpm:"darktable-tools-basecurve~4.6.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"darktable-tools-noise", rpm:"darktable-tools-noise~4.6.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"digikam", rpm:"digikam~8.4.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikam-devel", rpm:"lib64digikam-devel~8.4.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamcore8.4.0", rpm:"lib64digikamcore8.4.0~8.4.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamdatabase8.4.0", rpm:"lib64digikamdatabase8.4.0~8.4.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digikamgui8.4.0", rpm:"lib64digikamgui8.4.0~8.4.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64raw-devel", rpm:"lib64raw-devel~0.20.2~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64raw20", rpm:"lib64raw20~0.20.2~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64raw_r20", rpm:"lib64raw_r20~0.20.2~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikam-devel", rpm:"libdigikam-devel~8.4.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamcore8.4.0", rpm:"libdigikamcore8.4.0~8.4.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamdatabase8.4.0", rpm:"libdigikamdatabase8.4.0~8.4.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigikamgui8.4.0", rpm:"libdigikamgui8.4.0~8.4.0~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw", rpm:"libraw~0.20.2~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-devel", rpm:"libraw-devel~0.20.2~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw-tools", rpm:"libraw-tools~0.20.2~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw20", rpm:"libraw20~0.20.2~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraw_r20", rpm:"libraw_r20~0.20.2~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"showfoto", rpm:"showfoto~8.4.0~1.1.mga9", rls:"MAGEIA9"))) {
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
