# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21170.1");
  script_cve_id("CVE-2025-5263", "CVE-2025-5264", "CVE-2025-5265", "CVE-2025-5266", "CVE-2025-5267", "CVE-2025-5268", "CVE-2025-5269", "CVE-2025-5283", "CVE-2025-6424", "CVE-2025-6425", "CVE-2025-6426", "CVE-2025-6429", "CVE-2025-6430", "CVE-2025-8027", "CVE-2025-8028", "CVE-2025-8029", "CVE-2025-8030", "CVE-2025-8031", "CVE-2025-8032", "CVE-2025-8033", "CVE-2025-8034", "CVE-2025-8035", "CVE-2025-9179", "CVE-2025-9180", "CVE-2025-9181", "CVE-2025-9185");
  script_tag(name:"creation_date", value:"2025-12-11 12:28:02 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-15T05:47:36+0000");
  script_tag(name:"last_modification", value:"2025-12-15 05:47:36 +0000 (Mon, 15 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 14:15:43 +0000 (Thu, 21 Aug 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21170-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21170-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521170-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248162");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023500.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozjs128' package(s) announced via the SUSE-SU-2025:21170-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mozjs128 fixes the following issues:

- Update to version 128.14.0 (bsc#1248162):
 + CVE-2025-9179: Sandbox escape due to invalid pointer in the
 Audio/Video: GMP component
 + CVE-2025-9180: Same-origin policy bypass in the Graphics:
 Canvas2D component
 + CVE-2025-9181: Uninitialized memory in the JavaScript Engine
 component
 + CVE-2025-9185: Memory safety bugs fixed in Firefox ESR 115.27,
 Firefox ESR 128.14, Thunderbird ESR 128.14, Firefox ESR 140.2,
 Thunderbird ESR 140.2, Firefox 142 and Thunderbird 142

- Update to version 128.13.0:
 + CVE-2025-8027: JavaScript engine only wrote partial return
 value to stack
 + CVE-2025-8028: Large branch table could lead to truncated
 instruction
 + CVE-2025-8029: javascript: URLs executed on object and embed
 tags
 + CVE-2025-8030: Potential user-assisted code execution in 'Copy
 as cURL' command
 + CVE-2025-8031: Incorrect URL stripping in CSP reports
 + CVE-2025-8032: XSLT documents could bypass CSP
 + CVE-2025-8033: Incorrect JavaScript state machine for
 generators
 + CVE-2025-8034: Memory safety bugs fixed in Firefox ESR 115.26,
 Firefox ESR 128.13, Thunderbird ESR 128.13, Firefox ESR 140.1,
 Thunderbird ESR 140.1, Firefox 141 and Thunderbird 141
 + CVE-2025-8035: Memory safety bugs fixed in Firefox ESR 128.13,
 Thunderbird ESR 128.13, Firefox ESR 140.1, Thunderbird ESR
 140.1, Firefox 141 and Thunderbird 141

- Update to version 128.12.0:
 + CVE-2025-6424: Use-after-free in FontFaceSet
 + CVE-2025-6425: The WebCompat WebExtension shipped with Firefox
 exposed a persistent UUID
 + CVE-2025-6426: No warning when opening executable terminal
 files on macOS
 + CVE-2025-6429: Incorrect parsing of URLs could have allowed
 embedding of youtube.com
 + CVE-2025-6430: Content-Disposition header ignored when a file
 is included in an embed or object tag

- Update to version 128.11.0:
 + CVE-2025-5283: Double-free in libvpx encoder
 + CVE-2025-5263: Error handling for script execution was
 incorrectly isolated from web content
 + CVE-2025-5264: Potential local code execution in 'Copy as cURL'
 command
 + CVE-2025-5265: Potential local code execution in 'Copy as cURL'
 command
 + CVE-2025-5266: Script element events leaked cross-origin
 resource status
 + CVE-2025-5267: Clickjacking vulnerability could have led to
 leaking saved payment card details
 + CVE-2025-5268: Memory safety bugs fixed in Firefox 139,
 Thunderbird 139, Firefox ESR 128.11, and Thunderbird 128.11
 + CVE-2025-5269: Memory safety bug fixed in Firefox ESR 128.11
 and Thunderbird 128.11");

  script_tag(name:"affected", value:"'mozjs128' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmozjs-128-0", rpm:"libmozjs-128-0~128.14.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs128", rpm:"mozjs128~128.14.0~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozjs128-devel", rpm:"mozjs128-devel~128.14.0~160000.1.1", rls:"SLES16.0.0"))) {
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
