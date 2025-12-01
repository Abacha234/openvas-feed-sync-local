# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0280");
  script_cve_id("CVE-2024-12718", "CVE-2024-9287", "CVE-2025-0938", "CVE-2025-1795", "CVE-2025-4138", "CVE-2025-4330", "CVE-2025-4435", "CVE-2025-4516", "CVE-2025-4517", "CVE-2025-8194");
  script_tag(name:"creation_date", value:"2025-11-13 04:11:10 +0000 (Thu, 13 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-10 18:47:16 +0000 (Mon, 10 Feb 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0280)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0280");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0280.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34007");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34285");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/4FRAYUVWW2DYX7RTRPVFLFADRHABRVQN/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/IUW6UXZQE7B4PPK3PK3NZAWP5PVOU5L3/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NNC4GZYGFZ76A7NUZ5BG2CMGVR32LXCG/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7488-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/05/16/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/06/24/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/07/28/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3' package(s) announced via the MGASA-2025-0280 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"URL parser allowed square brackets in domain names. (CVE-2025-0938)
Mishandling of comma during folding and unicode-encoding of email
headers. (CVE-2025-1795)
Virtual environment (venv) activation scripts don't quote paths.
(CVE-2024-9287)
Use-after-free in 'unicode_escape' decoder with error handler.
(CVE-2025-4516)
Bypass extraction filter to modify file metadata outside extraction
directory. (CVE-2024-12718)
Bypassing extraction filter to create symlinks to arbitrary targets
outside extraction directory. (CVE-2025-4138)
Extraction filter bypass for linking outside extraction directory.
(CVE-2025-4330)
Tarfile extracts filtered members when errorlevel=0. (CVE-2025-4435)
Arbitrary writes via tarfile realpath overflow. (CVE-2025-4517)
Tarfile infinite loop during parsing with negative member offset.
(CVE-2025-8194)");

  script_tag(name:"affected", value:"'python3' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64python3-devel", rpm:"lib64python3-devel~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10", rpm:"lib64python3.10~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10-stdlib", rpm:"lib64python3.10-stdlib~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python3.10-testsuite", rpm:"lib64python3.10-testsuite~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3-devel", rpm:"libpython3-devel~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10", rpm:"libpython3.10~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10-stdlib", rpm:"libpython3.10-stdlib~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3.10-testsuite", rpm:"libpython3.10-testsuite~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-docs", rpm:"python3-docs~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3", rpm:"tkinter3~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter3-apps", rpm:"tkinter3-apps~3.10.18~1.4.mga9", rls:"MAGEIA9"))) {
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
