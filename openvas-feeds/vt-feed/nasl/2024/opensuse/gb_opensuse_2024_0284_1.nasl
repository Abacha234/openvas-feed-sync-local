# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833179");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-49933", "CVE-2023-49935", "CVE-2023-49936", "CVE-2023-49937", "CVE-2023-49938");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 17:17:34 +0000 (Thu, 21 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:19 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for slurm (SUSE-SU-2024:0284-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0284-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KRNWHWFZ3CMFRIMCQUQHEZNOIO4BPQIW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm'
  package(s) announced via the SUSE-SU-2024:0284-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm fixes the following issues:

  Update to slurm 23.02.6:

  Security fixes:

  * CVE-2023-49933: Prevent message extension attacks that could bypass the
      message hash. (bsc#1218046)

  * CVE-2023-49935: Prevent message hash bypass in slurmd which can allow an
      attacker to reuse root-level MUNGE tokens and escalate permissions.
      (bsc#1218049)

  * CVE-2023-49936: Prevent NULL pointer dereference on `size_valp` overflow.
      (bsc#1218050)

  * CVE-2023-49937: Prevent double-xfree() on error in
      `_unpack_node_reg_resp()`. (bsc#1218051)

  * CVE-2023-49938: Prevent modified `sbcast` RPCs from opening a file with the
      wrong group permissions. (bsc#1218053)

  Other fixes:

  * Add missing service file for slurmrestd (bsc#1217711).

  * Fix slurm upgrading to incompatible versions (bsc#1216869).

  ##");

  script_tag(name:"affected", value:"'slurm' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
