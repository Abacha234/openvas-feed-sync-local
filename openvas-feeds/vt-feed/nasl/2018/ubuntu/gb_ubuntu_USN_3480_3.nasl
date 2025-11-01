# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843719");
  script_cve_id("CVE-2017-14177", "CVE-2017-14180");
  script_tag(name:"creation_date", value:"2018-10-26 04:11:02 +0000 (Fri, 26 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3480-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3480-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3480-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1733366");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apport' package(s) announced via the USN-3480-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3480-2 fixed regressions in Apport. The update introduced a new regression in the container support. This update addresses the problem.

We apologize for the inconvenience.

Original advisory details:

 Sander Bos discovered that Apport incorrectly handled core dumps for setuid
 binaries. A local attacker could use this issue to perform a denial of service
 via resource exhaustion or possibly gain root privileges. (CVE-2017-14177)

 Sander Bos discovered that Apport incorrectly handled core dumps for processes
 in a different PID namespace. A local attacker could use this issue to perform
 a denial of service via resource exhaustion or possibly gain root privileges.
 (CVE-2017-14180)");

  script_tag(name:"affected", value:"'apport' package(s) on Ubuntu 16.04, Ubuntu 17.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
