# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856346");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-48560", "CVE-2023-27043", "CVE-2023-52425", "CVE-2024-0450");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 02:03:16 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:00:31 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for python (SUSE-SU-2024:1862-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1862-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3YSE4IOP4ISWHX3ARM75WVNBEW5HPEM3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the SUSE-SU-2024:1862-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python fixes the following issues:

  * CVE-2023-52425: Fixed using the system libexpat (bsc#1219559).

  * CVE-2023-27043: Modified fix for unicode string handling in
      email.utils.parseaddr() (bsc#1222537).

  * CVE-2022-48560: Fixed use-after-free in Python via heappushpop in heapq
      (bsc#1214675).

  * CVE-2024-0450: Detect the vulnerability of the 'quoted-overlap' zipbomb
      (bsc#1221854).

  Bug fixes:

  * Switch off tests. ONLY FOR FACTORY!!! (bsc#1219306).

  * Build with -std=gnu89 to build correctly with gcc14 (bsc#1220970).

  * Switch from %patchN style to the %patch -P N one.

  ##");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
