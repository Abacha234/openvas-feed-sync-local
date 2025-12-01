# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4174.1");
  script_cve_id("CVE-2025-11708", "CVE-2025-11709", "CVE-2025-11710", "CVE-2025-11711", "CVE-2025-11712", "CVE-2025-11713", "CVE-2025-11714", "CVE-2025-11715", "CVE-2025-13012", "CVE-2025-13013", "CVE-2025-13014", "CVE-2025-13015", "CVE-2025-13016", "CVE-2025-13017", "CVE-2025-13018", "CVE-2025-13019", "CVE-2025-13020");
  script_tag(name:"creation_date", value:"2025-11-26 04:15:37 +0000 (Wed, 26 Nov 2025)");
  script_version("2025-11-26T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-26 05:40:08 +0000 (Wed, 26 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4174-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254174-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253188");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023323.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2025:4174-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

- Update to Firefox Extended Support Release 140.5.0 ESR (bsc#1253188)
- CVE-2025-13012: Race condition in the Graphics component.
- CVE-2025-13016: Incorrect boundary conditions in the JavaScript: WebAssembly component.
- CVE-2025-13017: Same-origin policy bypass in the DOM: Notifications component.
- CVE-2025-13018: Mitigation bypass in the DOM: Security component.
- CVE-2025-13019: Same-origin policy bypass in the DOM: Workers component.
- CVE-2025-13013: Mitigation bypass in the DOM: Core & HTML component.
- CVE-2025-13020: Use-after-free in the WebRTC: Audio/Video component.
- CVE-2025-13014: Use-after-free in the Audio/Video component.
- CVE-2025-13015: Spoofing issue in Firefox.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.5.0~112.289.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.5.0~112.289.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.5.0~112.289.1", rls:"SLES12.0SP5"))) {
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
