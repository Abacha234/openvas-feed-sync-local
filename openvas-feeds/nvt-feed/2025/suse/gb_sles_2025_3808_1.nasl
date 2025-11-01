# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.3808.1");
  script_cve_id("CVE-2025-11708", "CVE-2025-11709", "CVE-2025-11710", "CVE-2025-11711", "CVE-2025-11712", "CVE-2025-11713", "CVE-2025-11714", "CVE-2025-11715");
  script_tag(name:"creation_date", value:"2025-10-29 04:15:57 +0000 (Wed, 29 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:3808-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3808-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253808-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251263");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-October/023036.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2025:3808-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Update to Firefox Extended Support Release 140.4.0 ESR (bsc#1251263).

- CVE-2025-11708: Use-after-free in MediaTrackGraphImpl::GetInstance()
- CVE-2025-11709: Out of bounds read/write in a privileged process triggered by WebGL textures
- CVE-2025-11710: Cross-process information leaked due to malicious IPC messages
- CVE-2025-11711: Some non-writable Object properties could be modified
- CVE-2025-11712: An OBJECT tag type attribute overrode browser behavior on web resources without a content-type
- CVE-2025-11713: Potential user-assisted code execution in 'Copy as cURL' command
- CVE-2025-11714: Memory safety bugs fixed in Firefox ESR 115.29, Firefox ESR 140.4, Thunderbird ESR 140.4, Firefox 144 and Thunderbird 144
- CVE-2025-11715: Memory safety bugs fixed in Firefox ESR 140.4, Thunderbird ESR 140.4, Firefox 144 and Thunderbird 144");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.4.0~112.286.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.4.0~112.286.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.4.0~112.286.1", rls:"SLES12.0SP5"))) {
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
