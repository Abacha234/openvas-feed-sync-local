# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856351");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2013-4235");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-13 15:30:11 +0000 (Fri, 13 Dec 2019)");
  script_tag(name:"creation_date", value:"2024-08-20 04:00:44 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for shadow (SUSE-SU-2024:2658-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2658-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VXWWXW42PRSSFA47EZ6OWPY7BH5VAHAC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shadow'
  package(s) announced via the SUSE-SU-2024:2658-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for shadow fixes the following issues:

  * CVE-2013-4235: Fixed a race condition when copying and removing directory
      trees (bsc#916845).

  ##");

  script_tag(name:"affected", value:"'shadow' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
