# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840427");
  script_tag(name:"creation_date", value:"2010-04-30 12:39:22 +0000 (Fri, 30 Apr 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-931-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-931-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-931-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/567913");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg, ffmpeg-debian' package(s) announced via the USN-931-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-931-1 fixed vulnerabilities in FFmpeg. The update introduced a
regression when trying to play certain multimedia files. This update fixes
the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that FFmpeg contained multiple security issues when
 handling certain multimedia files. If a user were tricked into opening a
 crafted multimedia file, an attacker could cause a denial of service via
 application crash, or possibly execute arbitrary code with the privileges
 of the user invoking the program.");

  script_tag(name:"affected", value:"'ffmpeg, ffmpeg-debian' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
