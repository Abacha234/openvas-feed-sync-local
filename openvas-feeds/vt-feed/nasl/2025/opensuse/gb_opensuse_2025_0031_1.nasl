# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856897");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2024-6655");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 15:15:12 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2025-01-08 05:00:07 +0000 (Wed, 08 Jan 2025)");
  script_name("openSUSE: Security Advisory for gtk3 (SUSE-SU-2025:0031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0031-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NP2KWSSOA4KK46LAFXUSTDF7MVZESZHH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk3'
  package(s) announced via the SUSE-SU-2025:0031-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gtk3 fixes the following issues:

  * CVE-2024-6655: Fixed library injection from current working directory
      (bsc#1228120).

  Other fixes:

  - Updated to version 3.24.43");

  script_tag(name:"affected", value:"'gtk3' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
