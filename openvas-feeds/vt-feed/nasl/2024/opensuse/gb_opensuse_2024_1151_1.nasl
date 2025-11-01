# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856052");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-2004", "CVE-2024-2398");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-04-09 01:06:33 +0000 (Tue, 09 Apr 2024)");
  script_name("openSUSE: Security Advisory for curl (SUSE-SU-2024:1151-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1151-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HCHDIZ7JX5FNXP5DQCAJZZI2KY3TGM3I");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl'
  package(s) announced via the SUSE-SU-2024:1151-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl fixes the following issues:

  * CVE-2024-2004: Fix the uUsage of disabled protocol logic. (bsc#1221665)

  * CVE-2024-2398: Fix HTTP/2 push headers memory-leak. (bsc#1221667)

  ##");

  script_tag(name:"affected", value:"'curl' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
