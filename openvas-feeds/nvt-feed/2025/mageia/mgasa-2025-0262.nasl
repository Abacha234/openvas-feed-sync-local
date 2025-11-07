# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0262");
  script_cve_id("CVE-2025-1153", "CVE-2025-1176", "CVE-2025-1178", "CVE-2025-1181", "CVE-2025-1182");
  script_tag(name:"creation_date", value:"2025-11-06 04:12:34 +0000 (Thu, 06 Nov 2025)");
  script_version("2025-11-06T05:40:15+0000");
  script_tag(name:"last_modification", value:"2025-11-06 05:40:15 +0000 (Thu, 06 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-03 17:28:09 +0000 (Mon, 03 Mar 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0262)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0262");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0262.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34180");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7423-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the MGASA-2025-0262 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNU Binutils format.c bfd_set_format memory corruption. (CVE-2025-1153)
GNU Binutils ld elflink.c _bfd_elf_gc_mark_rsec heap-based overflow.
(CVE-2025-1176)
GNU Binutils ld libbfd.c bfd_putl64 memory corruption. (CVE-2025-1178)
GNU Binutils ld elflink.c _bfd_elf_gc_mark_rsec memory corruption.
(CVE-2025-1181)
GNU Binutils ld elflink.c bfd_elf_reloc_symbol_deleted_p memory
corruption. (CVE-2025-1182)");

  script_tag(name:"affected", value:"'binutils' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.40~11.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64binutils-devel", rpm:"lib64binutils-devel~2.40~11.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbinutils-devel", rpm:"libbinutils-devel~2.40~11.2.mga9", rls:"MAGEIA9"))) {
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
