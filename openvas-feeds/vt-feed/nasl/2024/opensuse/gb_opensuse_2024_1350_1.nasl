# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856096");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-2609", "CVE-2024-3302", "CVE-2024-3852", "CVE-2024-3854", "CVE-2024-3857", "CVE-2024-3859", "CVE-2024-3861", "CVE-2024-3863", "CVE-2024-3864");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 16:52:27 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-04-23 01:06:02 +0000 (Tue, 23 Apr 2024)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (SUSE-SU-2024:1350-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1350-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/O4QMBMG3YZRR5RFIN5XUIOUMBW2A4KKA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the SUSE-SU-2024:1350-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

  Update to Firefox Extended Support Release 115.10.0 ESR (MSFA 2024-19)
  (bsc#1222535):

  * CVE-2024-3852: GetBoundName in the JIT returned the wrong object

  * CVE-2024-3854: Out-of-bounds-read after mis-optimized switch statement

  * CVE-2024-3857: Incorrect JITting of arguments led to use-after-free during
      garbage collection

  * CVE-2024-2609: Permission prompt input delay could expire when not in focus

  * CVE-2024-3859: Integer-overflow led to out-of-bounds-read in the OpenType
      sanitizer

  * CVE-2024-3861: Potential use-after-free due to AlignedBuffer self-move

  * CVE-2024-3863: Download Protections were bypassed by .xrm-ms files on
      Windows

  * CVE-2024-3302: Denial of Service using HTTP/2 CONTINUATION frames

  * CVE-2024-3864: Memory safety bug fixed in Firefox 125, Firefox ESR 115.10,
      and Thunderbird 115.10

  ##");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
