# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63746");
  script_cve_id("CVE-2008-5239", "CVE-2009-0698");
  script_tag(name:"creation_date", value:"2009-04-06 18:58:11 +0000 (Mon, 06 Apr 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-746-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-746-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-746-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/322834");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xine-lib' package(s) announced via the USN-746-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the 4xm demuxer in xine-lib did not correctly handle
a large current_track value in a 4xm file, resulting in an integer
overflow. If a user or automated system were tricked into opening a
specially crafted 4xm movie file, an attacker could crash xine-lib or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2009-0698)

USN-710-1 provided updated xine-lib packages to fix multiple security
vulnerabilities. The security patch to fix CVE-2008-5239 introduced a
regression causing some media files to be unplayable. This update corrects
the problem. We apologize for the inconvenience.

Original advisory details:
 It was discovered that the input handlers in xine-lib did not correctly
 handle certain error codes, resulting in out-of-bounds reads and heap-
 based buffer overflows. If a user or automated system were tricked into
 opening a specially crafted file, stream, or URL, an attacker could
 execute arbitrary code as the user invoking the program. (CVE-2008-5239)");

  script_tag(name:"affected", value:"'xine-lib' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
