# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856784");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-11691", "CVE-2024-11692", "CVE-2024-11693", "CVE-2024-11694", "CVE-2024-11695", "CVE-2024-11696", "CVE-2024-11697", "CVE-2024-11698", "CVE-2024-11699");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-12-04 05:00:31 +0000 (Wed, 04 Dec 2024)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (SUSE-SU-2024:4148-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4148-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FCZLKT562QZALXOZD64KU3NZXVB4VHI3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the SUSE-SU-2024:4148-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  * Mozilla Thunderbird 128.5

  * fixed: IMAP could crash when reading cached messages

  * fixed: Enabling 'Show Folder Size' on Maildir profile could render
      Thunderbird unusable

  * fixed: Messages corrupted by folder compaction were only fixed by user
      intervention

  * fixed: Reading a message from past the end of an mbox file did not cause an
      error

  * fixed: View -> Folders had duplicate F access keys

  * fixed: Add-ons adding columns to the message list could fail and cause
      display issue

  * fixed: 'Empty trash on exit' and 'Expunge inbox on exit' did not always work

  * fixed: Selecting a display option in View -> Tasks did not apply in the Task
      interface

  * fixed: Security fixes MFSA 2024-68 (bsc#1233695)

  * CVE-2024-11691 Out-of-bounds write in Apple GPU drivers via WebGL

  * CVE-2024-11692 Select list elements could be shown over another site

  * CVE-2024-11693 Download Protections were bypassed by .library-ms files on
      Windows

  * CVE-2024-11694 CSP Bypass and XSS Exposure via Web Compatibility Shims

  * CVE-2024-11695 URL Bar Spoofing via Manipulated Punycode and Whitespace
      Characters

  * CVE-2024-11696 Unhandled Exception in Add-on Signature Verification

  * CVE-2024-11697 Improper Keypress Handling in Executable File Confirmation
      Dialog

  * CVE-2024-11698 Fullscreen Lock-Up When Modal Dialog Interrupts Transition on
      macOS

  * CVE-2024-11699 Memory safety bugs fixed in Firefox 133, Thunderbird 133,
      Firefox ESR 128.5, and Thunderbird 128.5

  * Handle upstream changes with esr-prefix of desktop-file (bsc#1233650)");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
