# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856378");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-4367", "CVE-2024-4767", "CVE-2024-4768", "CVE-2024-4769", "CVE-2024-4770", "CVE-2024-4777");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-22 16:42:03 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2024-08-20 04:08:46 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (SUSE-SU-2024:1858-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1858-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GBCFBU3XCENDBK23ZXEWN7JMFBPOM76Q");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the SUSE-SU-2024:1858-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  Update to version 115.11 (bsc#1224056):

  * CVE-2024-4367: Arbitrary JavaScript execution in PDF.js

  * CVE-2024-4767: IndexedDB files retained in private browsing mode

  * CVE-2024-4768: Potential permissions request bypass via clickjacking

  * CVE-2024-4769: Cross-origin responses could be distinguished between script
      and non-script content-types

  * CVE-2024-4770: Use-after-free could occur when printing to PDF

  * CVE-2024-4777: Memory safety bugs fixed in Firefox 126, Firefox ESR 115.11,
      and Thunderbird 115.11

  * fixed: Splitter arrow between task list and task description did not behave
      as expected

  * fixed: Calendar Event Attendees dialog had incorrectly sized rows

  ##");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
