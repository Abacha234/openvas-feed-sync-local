# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0265");
  script_cve_id("CVE-2025-9732");
  script_tag(name:"creation_date", value:"2025-11-07 04:09:13 +0000 (Fri, 07 Nov 2025)");
  script_version("2025-11-07T05:40:09+0000");
  script_tag(name:"last_modification", value:"2025-11-07 05:40:09 +0000 (Fri, 07 Nov 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-05 20:21:46 +0000 (Fri, 05 Sep 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0265)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0265");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0265.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34718");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2025/11/msg00006.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcmtk' package(s) announced via the MGASA-2025-0265 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was identified in DCMTK up to 3.6.9. This affects an
unknown function in the library
dcmimage/include/dcmtk/dcmimage/diybrpxt.h of the component dcm2img.
Such manipulation leads to memory corruption. Local access is required
to approach this attack. The name of the patch is 7ad81d69b. It is best
practice to apply a patch to resolve this issue.");

  script_tag(name:"affected", value:"'dcmtk' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"dcmtk", rpm:"dcmtk~3.6.7~4.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dcmtk-devel", rpm:"lib64dcmtk-devel~3.6.7~4.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64dcmtk17", rpm:"lib64dcmtk17~3.6.7~4.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk-devel", rpm:"libdcmtk-devel~3.6.7~4.6.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk17", rpm:"libdcmtk17~3.6.7~4.6.mga9", rls:"MAGEIA9"))) {
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
