# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891615");
  script_cve_id("CVE-2013-7108", "CVE-2013-7205", "CVE-2014-1878", "CVE-2016-9566", "CVE-2018-18245");
  script_tag(name:"creation_date", value:"2018-12-27 23:00:00 +0000 (Thu, 27 Dec 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-25 11:29:00 +0000 (Tue, 25 Dec 2018)");

  script_name("Debian: Security Advisory (DLA-1615)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1615");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1615");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nagios3' package(s) announced via the DLA-1615 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues were corrected in nagios3, a monitoring and management system for hosts, services and networks.

CVE-2018-18245

Maximilian Boehner of usd AG found a cross-site scripting (XSS) vulnerability in Nagios Core. This vulnerability allows attackers to place malicious JavaScript code into the web frontend through manipulation of plugin output. In order to do this the attacker needs to be able to manipulate the output returned by nagios checks, e.g. by replacing a plugin on one of the monitored endpoints. Execution of the payload then requires that an authenticated user creates an alert summary report which contains the corresponding output.

CVE-2016-9566

It was discovered that local users with access to an account in the nagios group are able to gain root privileges via a symlink attack on the debug log file.

CVE-2014-1878

An issue was corrected that allowed remote attackers to cause a stack-based buffer overflow and subsequently a denial of service (segmentation fault) via a long message to cmd.cgi.

CVE-2013-7205 / CVE-2013-7108 A flaw was corrected in Nagios that could be exploited to cause a denial-of-service. This vulnerability is induced due to an off-by-one error within the process_cgivars() function, which can be exploited to cause an out-of-bounds read by sending a specially-crafted key value to the Nagios web UI.

For Debian 8 Jessie, these problems have been fixed in version 3.5.1.dfsg-2+deb8u1.

We recommend that you upgrade your nagios3 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'nagios3' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);