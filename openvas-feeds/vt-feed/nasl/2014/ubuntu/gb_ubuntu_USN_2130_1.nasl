# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841741");
  script_cve_id("CVE-2013-4286", "CVE-2013-4322", "CVE-2014-0033", "CVE-2014-0050");
  script_tag(name:"creation_date", value:"2014-03-12 04:08:22 +0000 (Wed, 12 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2130-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2130-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2130-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6, tomcat7' package(s) announced via the USN-2130-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly handled certain inconsistent
HTTP headers. A remote attacker could possibly use this flaw to conduct
request smuggling attacks. (CVE-2013-4286)

It was discovered that Tomcat incorrectly handled certain requests
submitted using chunked transfer encoding. A remote attacker could use this
flaw to cause the Tomcat server to stop responding, resulting in a denial
of service. (CVE-2013-4322)

It was discovered that Tomcat incorrectly applied the disableURLRewriting
setting when handling a session id in a URL. A remote attacker could
possibly use this flaw to conduct session fixation attacks. This issue
only applied to Ubuntu 12.04 LTS. (CVE-2014-0033)

It was discovered that Tomcat incorrectly handled malformed Content-Type
headers and multipart requests. A remote attacker could use this flaw to
cause the Tomcat server to stop responding, resulting in a denial of
service. This issue only applied to Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2014-0050)");

  script_tag(name:"affected", value:"'tomcat6, tomcat7' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
