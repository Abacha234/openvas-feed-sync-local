# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856046");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-52425", "CVE-2024-28757");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 02:03:16 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-04-09 01:06:24 +0000 (Tue, 09 Apr 2024)");
  script_name("openSUSE: Security Advisory for expat (SUSE-SU-2024:1129-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1129-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/U7W3WDKQMYVFIVQ66XXZYJLM6HBVQQTN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat'
  package(s) announced via the SUSE-SU-2024:1129-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for expat fixes the following issues:

  * CVE-2023-52425: Fixed a DoS caused by processing large tokens. (bsc#1219559)

  * CVE-2024-28757: Fixed an XML Entity Expansion. (bsc#1221289)

  ##");

  script_tag(name:"affected", value:"'expat' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
