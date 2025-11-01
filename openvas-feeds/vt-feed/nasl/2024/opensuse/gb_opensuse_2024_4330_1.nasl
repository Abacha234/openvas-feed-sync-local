# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856851");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-43374", "CVE-2024-47814");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-12-17 05:00:22 +0000 (Tue, 17 Dec 2024)");
  script_name("openSUSE: Security Advisory for vim (SUSE-SU-2024:4330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4330-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M5C4Q3E75NCX7ADSR5356G7DHQ7MGP2H");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim'
  package(s) announced via the SUSE-SU-2024:4330-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

  * CVE-2024-47814: Fixed use-after-free when closing buffers in Vim
      (bsc#1231373)

  * CVE-2024-43374: Fixed use-after-free in alist_add() (bsc#1229238)

  Other fixes:

  * Updated to version 9.1.0836");

  script_tag(name:"affected", value:"'vim' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
