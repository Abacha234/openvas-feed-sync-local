# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21021.1");
  script_cve_id("CVE-2025-10527", "CVE-2025-10528", "CVE-2025-10529", "CVE-2025-10532", "CVE-2025-10533", "CVE-2025-10536", "CVE-2025-10537", "CVE-2025-11708", "CVE-2025-11709", "CVE-2025-11710", "CVE-2025-11711", "CVE-2025-11712", "CVE-2025-11713", "CVE-2025-11714", "CVE-2025-11715", "CVE-2025-13012", "CVE-2025-13013", "CVE-2025-13014", "CVE-2025-13015", "CVE-2025-13016", "CVE-2025-13017", "CVE-2025-13018", "CVE-2025-13019", "CVE-2025-13020");
  script_tag(name:"creation_date", value:"2025-11-28 04:13:19 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T05:40:45+0000");
  script_tag(name:"last_modification", value:"2025-11-28 05:40:45 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21021-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21021-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521021-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253188");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-November/023380.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2025:21021-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Changes in MozillaFirefox:

Firefox Extended Support Release 140.5.0 ESR:

* Fixed: Various security fixes (MFSA 2025-88 bsc#1253188):

 * CVE-2025-13012
 Race condition in the Graphics component
 * CVE-2025-13016
 Incorrect boundary conditions in the JavaScript: WebAssembly
 component
 * CVE-2025-13017
 Same-origin policy bypass in the DOM: Notifications component
 * CVE-2025-13018
 Mitigation bypass in the DOM: Security component
 * CVE-2025-13019
 Same-origin policy bypass in the DOM: Workers component
 * CVE-2025-13013
 Mitigation bypass in the DOM: Core & HTML component
 * CVE-2025-13020
 Use-after-free in the WebRTC: Audio/Video component
 * CVE-2025-13014
 Use-after-free in the Audio/Video component
 * CVE-2025-13015
 Spoofing issue in Firefox

- Firefox Extended Support Release 140.4.0 ESR
 * Fixed: Various security fixes.
 MFSA 2025-83 (bsc#1251263)
 * CVE-2025-11708
 Use-after-free in MediaTrackGraphImpl::GetInstance()
 * CVE-2025-11709
 Out of bounds read/write in a privileged process triggered by
 WebGL textures
 * CVE-2025-11710
 Cross-process information leaked due to malicious IPC
 messages
 * CVE-2025-11711
 Some non-writable Object properties could be modified
 * CVE-2025-11712
 An OBJECT tag type attribute overrode browser behavior on web
 resources without a content-type
 * CVE-2025-11713
 Potential user-assisted code execution in 'Copy as cURL'
 command
 * CVE-2025-11714
 Memory safety bugs fixed in Firefox ESR 115.29, Firefox ESR
 140.4, Thunderbird ESR 140.4, Firefox 144 and Thunderbird 144
 * CVE-2025-11715
 Memory safety bugs fixed in Firefox ESR 140.4, Thunderbird
 ESR 140.4, Firefox 144 and Thunderbird 144

- Firefox Extended Support Release 140.3.1 ESR (bsc#1250452)
 * Fixed: Improved reliability when HTTP/3 connections fail:
 Firefox no longer forces HTTP/2 during fallback, allowing the
 server to choose the protocol and preventing stalls on some
 sites.

Firefox Extended Support Release 140.3.0 ESR

* Fixed: Various security fixes (MFSA 2025-75 bsc#1249391)

 * CVE-2025-10527
 Sandbox escape due to use-after-free in the Graphics:
 Canvas2D component
 * CVE-2025-10528
 Sandbox escape due to undefined behavior, invalid pointer in
 the Graphics: Canvas2D component
 * CVE-2025-10529
 Same-origin policy bypass in the Layout component
 * CVE-2025-10532
 Incorrect boundary conditions in the JavaScript: GC component
 * CVE-2025-10533
 Integer overflow in the SVG component
 * CVE-2025-10536
 Information disclosure in the Networking: Cache component
 * CVE-2025-10537
 Memory safety bugs fixed in Firefox ESR 140.3, Thunderbird
 ESR 140.3, Firefox 143 and Thunderbird 143");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.5.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.5.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.5.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~140.5.0~160000.1.1", rls:"SLES16.0.0"))) {
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
