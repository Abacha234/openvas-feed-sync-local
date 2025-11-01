# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856187");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-32002", "CVE-2024-32004", "CVE-2024-32020", "CVE-2024-32021", "CVE-2024-32465");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 20:40:28 +0000 (Thu, 23 May 2024)");
  script_tag(name:"creation_date", value:"2024-06-05 01:00:56 +0000 (Wed, 05 Jun 2024)");
  script_name("openSUSE: Security Advisory for git (SUSE-SU-2024:1807-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1807-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7R7ITNDWGHU4NLBVFRNH7UIKNQITT3RM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git'
  package(s) announced via the SUSE-SU-2024:1807-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for git fixes the following issues:

  * CVE-2024-32002: Fixed recursive clones on case-insensitive filesystems that
      support symbolic links are susceptible to case confusion (bsc#1224168).

  * CVE-2024-32004: Fixed arbitrary code execution during local clones
      (bsc#1224170).

  * CVE-2024-32020: Fixed file overwriting vulnerability during local clones
      (bsc#1224171).

  * CVE-2024-32021: Fixed git may create hardlinks to arbitrary user-readable
      files (bsc#1224172).

  * CVE-2024-32465: Fixed arbitrary code execution during clone operations
      (bsc#1224173).

  ##");

  script_tag(name:"affected", value:"'git' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
