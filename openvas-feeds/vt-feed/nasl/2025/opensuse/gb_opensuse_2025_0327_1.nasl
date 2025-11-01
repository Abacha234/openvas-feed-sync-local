# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.857025");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2018-14679", "CVE-2023-20197", "CVE-2024-20380", "CVE-2024-20505", "CVE-2024-20506", "CVE-2025-20128");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-12 17:28:47 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2025-02-04 05:00:06 +0000 (Tue, 04 Feb 2025)");
  script_name("openSUSE: Security Advisory for clamav (SUSE-SU-2025:0327-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0327-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DWG7AUMO3NQFYYFTEATZ4EVY257UW422");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav'
  package(s) announced via the SUSE-SU-2025:0327-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

  New version 1.4.2:

    * CVE-2025-20128, bsc#1236307: Fixed a possible buffer overflow read bug in
      the OLE2 file parser that could cause a denial-of-service (DoS) condition.

    * Start clamonacc with --fdpass to avoid errors due to clamd not being able to
      access user files. (bsc#1232242)

    * New version 1.4.1:

    * New version 1.4.0:

    * Added support for extracting ALZ archives.

    * Added support for extracting LHA/LZH archives.
    * Added the ability to disable image fuzzy hashing, if needed. For context,
      image fuzzy hashing is a detection mechanism useful for identifying malware
      by matching images included with the malware or phishing email/document.

    * New version 1.3.2:

    * CVE-2024-20506: Changed the logging module to disable following symlinks on
      Linux and Unix systems so as to prevent an attacker with existing access to
      the 'clamd' or 'freshclam' services from using a symlink to corrupt system
      files.

    * CVE-2024-20505: Fixed a possible out-of-bounds read bug in the PDF file
      parser that could cause a denial-of-service condition.
    * Removed unused Python modules from freshclam tests including deprecated
      'cgi' module that is expected to cause test failures in Python 3.13.
    * Fix unit test caused by expiring signing certificate.
    * Fixed a build issue on Windows with newer versions of Rust. Also upgraded
      GitHub Actions imports to fix CI failures.
    * Fixed an unaligned pointer dereference issue on select architectures.
    * Fixes to Jenkins CI pipeline.

    * New Version: 1.3.1:

    * CVE-2024-20380: Fixed a possible crash in the HTML file parser that could
      cause a denial-of-service (DoS) condition.

    * Updated select Rust dependencies to the latest versions.
    * Fixed a bug causing some text to be truncated when converting from UTF-16.
    * Fixed assorted complaints identified by Coverity static analysis.
    * Fixed a bug causing CVDs downloaded by the DatabaseCustomURL
    * Added the new 'valhalla' database name to the list of optional databases in
      preparation for future work.

    * New version: 1.3.0:

    * Added support for extracting and scanning attachments found in Microsoft
      OneNote section files. OneNote parsing will be enabled by default, but may
      be optionally disabled.

    * Added file type recognition for compiled Python ('.py ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'clamav' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
