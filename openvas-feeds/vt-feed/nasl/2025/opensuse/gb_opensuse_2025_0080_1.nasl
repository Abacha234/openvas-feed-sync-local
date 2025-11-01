# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856918");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2025-0237", "CVE-2025-0238", "CVE-2025-0239", "CVE-2025-0240", "CVE-2025-0241", "CVE-2025-0242", "CVE-2025-0243");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"creation_date", value:"2025-01-14 05:00:06 +0000 (Tue, 14 Jan 2025)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (SUSE-SU-2025:0080-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0080-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3TLV52643D5O3CTQECGW2XT2WTYPVUM3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the SUSE-SU-2025:0080-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  Update to Mozilla Thunderbird ESR 128.6 (MFSA 2025-05, bsc#1234991)

  Security fixes:

  * CVE-2025-0237 (bmo#1915257) WebChannel APIs susceptible to confused deputy
      attack

  * CVE-2025-0238 (bmo#1915535) Use-after-free when breaking lines in text

  * CVE-2025-0239 (bmo#1929156) Alt-Svc ALPN validation failure when redirected

  * CVE-2025-0240 (bmo#1929623) Compartment mismatch when parsing JavaScript
      JSON module

  * CVE-2025-0241 (bmo#1933023) Memory corruption when using JavaScript Text
      Segmentation

  * CVE-2025-0242 (bmo#1874523, bmo#1926454, bmo#1931873, bmo#1932169) Memory
      safety bugs fixed in Firefox 134, Thunderbird 134, Firefox ESR 115.19,
      Firefox ESR 128.6, Thunderbird 115.19, and Thunderbird 128.6

  * CVE-2025-0243 (bmo#1827142, bmo#1932783) Memory safety bugs fixed in Firefox
      134, Thunderbird 134, Firefox ESR 128.6, and Thunderbird 128.6

  Other fixes:

  * fixed: New mail notification was not hidden after reading the new message
      (bmo#1920077)

  * fixed: New mail notification could show for the wrong folder, causing
      repeated alerts (bmo#1926462)

  * fixed: macOS shortcut CMD+1 did not restore the main window when it was
      minimized (bmo#1857953)

  * fixed: Clicking the context menu 'Reply' button resulted in 'Reply-All'
      (bmo#1935883)

  * fixed: Switching from 'All', 'Unread', and 'Threads with unread' did not
      work (bmo#1921618)

  * fixed: Downloading message headers from a newsgroup could cause a hang
      (bmo#1931661)

  * fixed: Message list performance slow when many updates happened at once
      (bmo#1933104)

  * fixed: 'mailto:' links did not apply the compose format of the current
      identity (bmo#550414)

  * fixed: Authentication failure of AUTH PLAIN or AUTH LOGIN did not fall back
      to USERPASS (bmo#1928026)");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
