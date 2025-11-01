# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840905");
  script_cve_id("CVE-2012-0210", "CVE-2012-0211", "CVE-2012-0212");
  script_tag(name:"creation_date", value:"2012-02-21 13:30:44 +0000 (Tue, 21 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1366-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1366-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1366-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'devscripts' package(s) announced via the USN-1366-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Wise discovered that debdiff did not properly sanitize its input when
processing .dsc and .changes files. If debdiff processed a crafted file, an
attacker could execute arbitrary code with the privileges of the user invoking
the program. (CVE-2012-0210)

Raphael Geissert discovered that debdiff did not properly sanitize its input
when processing source packages. If debdiff processed an original source
tarball, with crafted filenames in the top-level directory, an attacker could
execute arbitrary code with the privileges of the user invoking the program.
(CVE-2012-0211)

Raphael Geissert discovered that debdiff did not properly sanitize its input
when processing filename parameters. If debdiff processed a crafted filename
parameter, an attacker could execute arbitrary code with the privileges of the
user invoking the program. (CVE-2012-0212)");

  script_tag(name:"affected", value:"'devscripts' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
