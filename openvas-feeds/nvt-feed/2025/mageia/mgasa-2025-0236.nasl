# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0236");
  script_cve_id("CVE-2025-20053", "CVE-2025-20109", "CVE-2025-21090", "CVE-2025-22839", "CVE-2025-22840", "CVE-2025-24305", "CVE-2025-26403", "CVE-2025-32086");
  script_tag(name:"creation_date", value:"2025-10-10 04:08:17 +0000 (Fri, 10 Oct 2025)");
  script_version("2025-10-10T05:39:02+0000");
  script_tag(name:"last_modification", value:"2025-10-10 05:39:02 +0000 (Fri, 10 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0236)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0236");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0236.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34629");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/releases/tag/microcode-20250812");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'microcode' package(s) announced via the MGASA-2025-0236 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated package updates AMD cpu microcode for processor family 19h,
adds AMD cpu microcode for processor family 1ah and fixes security
vulnerabilities for Intel processors:
Improper Isolation or Compartmentalization in the stream cache mechanism
for some Intel(r) Processors may allow an authenticated user to
potentially enable escalation of privilege via local access.
(CVE-2025-20109)
Sequence of processor instructions leads to unexpected behavior for some
Intel(r) Xeon(r) 6 Scalable processors may allow an authenticated user to
potentially enable escalation of privilege via local access.
(CVE-2025-22840)
Insufficient granularity of access control in the OOB-MSM for some
Intel(r) Xeon(r) 6 Scalable processors may allow a privileged user to
potentially enable escalation of privilege via adjacent access.
(CVE-2025-22839)
Improper handling of overlap between protected memory ranges for some
Intel(r) Xeon(r) 6 processor with Intel(r) TDX may allow a privileged user to
potentially enable escalation of privilege via local access.
(CVE-2025-22889)
Improper buffer restrictions for some Intel(r) Xeon(r) Processor firmware
with SGX enabled may allow a privileged user to potentially enable
escalation of privilege via local access. (CVE-2025-20053)
Insufficient control flow management in the Alias Checking Trusted
Module (ACTM) firmware for some Intel(r) Xeon(r) processors may allow a
privileged user to potentially enable escalation of privilege via local
access. (CVE-2025-24305)
Missing reference to active allocated resource for some Intel(r) Xeon(r)
processors may allow an authenticated user to potentially enable denial
of service via local access. (CVE-2025-21090)
Out-of-bounds write in the memory subsystem for some Intel(r) Xeon(r) 6
processors when using Intel(r) SGX or Intel(r) TDX may allow a privileged
user to potentially enable escalation of privilege via local access.
(CVE-2025-26403)
Improperly implemented security check for standard in the DDRIO
configuration for some Intel(r) Xeon(r) 6 Processors when using Intel(r) SGX
or Intel(r) TDX may allow a privileged user to potentially enable
escalation of privilege via local access. (CVE-2025-32086)");

  script_tag(name:"affected", value:"'microcode' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"microcode", rpm:"microcode~0.20250812~1.mga9.nonfree", rls:"MAGEIA9"))) {
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
