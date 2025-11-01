# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856653");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-47598", "CVE-2023-52752", "CVE-2024-35862", "CVE-2024-35864");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-24 01:12:36 +0000 (Fri, 24 May 2024)");
  script_tag(name:"creation_date", value:"2024-10-31 05:03:28 +0000 (Thu, 31 Oct 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 38 for SLE 15 SP3) (SUSE-SU-2024:3797-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3797-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YRSX2ZGVA64MPU4CZ47LWC6UVRLQCCGE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 38 for SLE 15 SP3)'
  package(s) announced via the SUSE-SU-2024:3797-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.3.18-150300_59_141 fixes several issues.

  The following security issues were fixed:

  * CVE-2021-47598: sch_cake: do not call cake_destroy() from cake_init()
      (bsc#1227471).

  * CVE-2023-52752: smb: client: fix use-after-free bug in
      cifs_debug_data_proc_show() (bsc#1225819).

  * CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted()
      (bsc#1225311).

  * CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break()
      (bsc#1225309).");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 38 for SLE 15 SP3)' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
