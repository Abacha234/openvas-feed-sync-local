# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856418");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-1753", "CVE-2024-23651", "CVE-2024-23652", "CVE-2024-23653", "CVE-2024-24786", "CVE-2024-28180", "CVE-2024-3727", "CVE-2024-41110");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 01:44:46 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-09-06 04:00:25 +0000 (Fri, 06 Sep 2024)");
  script_name("openSUSE: Security Advisory for buildah, docker (SUSE-SU-2024:3120-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3120-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EICVMKSN5VPGGTP2FPTZ53EY3T2SW6UR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah, docker'
  package(s) announced via the SUSE-SU-2024:3120-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah, docker fixes the following issues:

  Changes in docker: \- CVE-2024-23651: Fixed arbitrary files write due to race
  condition on mounts (bsc#1219267) \- CVE-2024-23652: Fixed insufficient
  validation of parent directory on mount (bsc#1219268) \- CVE-2024-23653: Fixed
  insufficient validation on entitlement on container creation via buildkit
  (bsc#1219438) \- CVE-2024-41110: A Authz zero length regression that could lead
  to authentication bypass was fixed (bsc#1228324)

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'buildah, docker' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
