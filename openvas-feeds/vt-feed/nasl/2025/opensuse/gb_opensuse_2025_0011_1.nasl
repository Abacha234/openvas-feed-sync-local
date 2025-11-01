# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856892");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2023-6917", "CVE-2024-45769", "CVE-2024-45770");
  script_tag(name:"cvss_base", value:"5.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-28 15:15:07 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"creation_date", value:"2025-01-07 08:15:11 +0000 (Tue, 07 Jan 2025)");
  script_name("openSUSE: Security Advisory for pcp (SUSE-SU-2025:0011-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0011-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M45327WKIPHO6GNOP772MN6LJRVARBPX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcp'
  package(s) announced via the SUSE-SU-2025:0011-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pcp fixes the following issues:

  Upgrade to 6.2.0 (bsc#1217826 / PED#8192):

  * CVE-2024-45770: Fixed symlink race (bsc#1230552).

  * CVE-2024-45769: Fixed pmstore corruption (bsc#1230551)

  * CVE-2023-6917: Fixed local privilege escalation from pcp user to root
      (bsc#1217826).

  Bug fixes:

  * Reintroduce libuv support for SLE >= 15 (bsc#1231345).

  * move pmlogger_daily into main package (bsc#1222815)");

  script_tag(name:"affected", value:"'pcp' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
