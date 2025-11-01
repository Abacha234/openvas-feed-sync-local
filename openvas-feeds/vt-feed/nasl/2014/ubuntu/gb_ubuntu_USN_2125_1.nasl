# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841733");
  script_cve_id("CVE-2014-1912");
  script_tag(name:"creation_date", value:"2014-03-04 05:20:18 +0000 (Tue, 04 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2125-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2125-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2125-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.6, python2.7, python3.2, python3.3' package(s) announced via the USN-2125-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ryan Smith-Roberts discovered that Python incorrectly handled buffer sizes
when using the socket.recvfrom_into() function. An attacker could possibly
use this issue to cause Python to crash, resulting in denial of service, or
possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'python2.6, python2.7, python3.2, python3.3' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
