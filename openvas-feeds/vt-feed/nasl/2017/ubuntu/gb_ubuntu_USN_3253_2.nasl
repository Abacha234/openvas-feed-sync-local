# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843202");
  script_cve_id("CVE-2013-7108", "CVE-2013-7205", "CVE-2014-1878", "CVE-2016-9566");
  script_tag(name:"creation_date", value:"2017-06-08 04:04:35 +0000 (Thu, 08 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3253-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3253-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3253-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1690380");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nagios3' package(s) announced via the USN-3253-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3253-1 fixed vulnerabilities in Nagios. The update prevented log files
from being displayed in the web interface. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Nagios incorrectly handled certain long strings. A
 remote authenticated attacker could use this issue to cause Nagios to
 crash, resulting in a denial of service, or possibly obtain sensitive
 information. (CVE-2013-7108, CVE-2013-7205)

 It was discovered that Nagios incorrectly handled certain long messages to
 cmd.cgi. A remote attacker could possibly use this issue to cause Nagios to
 crash, resulting in a denial of service. (CVE-2014-1878)

 Dawid Golunski discovered that Nagios incorrectly handled symlinks when
 accessing log files. A local attacker could possibly use this issue to
 elevate privileges. In the default installation of Ubuntu, this should be
 prevented by the Yama link restrictions. (CVE-2016-9566)");

  script_tag(name:"affected", value:"'nagios3' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
