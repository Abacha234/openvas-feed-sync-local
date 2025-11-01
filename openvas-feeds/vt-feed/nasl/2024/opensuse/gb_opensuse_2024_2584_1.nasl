# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856320");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-24575", "CVE-2024-24577");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 14:54:09 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-07-24 04:00:37 +0000 (Wed, 24 Jul 2024)");
  script_name("openSUSE: Security Advisory for libgit2 (SUSE-SU-2024:2584-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2584-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RJBE2DGR6PSBFOZBXVTCOSEMRXJM7Q6D");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgit2'
  package(s) announced via the SUSE-SU-2024:2584-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgit2 fixes the following issues:

  Update to 1.7.2:

  Security fixes:

  * CVE-2024-24577: Fixed arbitrary code execution due to heap corruption in
      git_index_add (bsc#1219660)

  * CVE-2024-24575: Fixed potential infinite loop condition in
      git_revparse_single() (bsc#1219664)

  Other fixes: \- A bug in the smart transport negotiation could have caused an
  out-of-bounds read when a remote server did not advertise capabilities.");

  script_tag(name:"affected", value:"'libgit2' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
