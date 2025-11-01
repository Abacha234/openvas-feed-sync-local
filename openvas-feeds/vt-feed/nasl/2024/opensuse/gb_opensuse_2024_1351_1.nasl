# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856088");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-46045");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-10 04:06:57 +0000 (Sat, 10 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-04-23 01:00:20 +0000 (Tue, 23 Apr 2024)");
  script_name("openSUSE: Security Advisory for graphviz (SUSE-SU-2024:1351-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1351-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UDSXMXWCIIUJIXJL4MVW5CLRX25ISWKW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphviz'
  package(s) announced via the SUSE-SU-2024:1351-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for graphviz fixes the following issues:

  * CVE-2023-46045: Fixed out-of-bounds read via a crafted config6a file
      (bsc#1219491)

  ##");

  script_tag(name:"affected", value:"'graphviz' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
