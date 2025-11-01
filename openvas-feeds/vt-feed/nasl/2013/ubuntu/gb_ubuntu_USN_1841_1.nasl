# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841442");
  script_cve_id("CVE-2012-3544", "CVE-2013-2067", "CVE-2013-2071");
  script_tag(name:"creation_date", value:"2013-05-31 04:27:48 +0000 (Fri, 31 May 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1841-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1841-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1841-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6, tomcat7' package(s) announced via the USN-1841-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly handled certain requests
submitted using chunked transfer encoding. A remote attacker could use this
flaw to cause the Tomcat server to stop responding, resulting in a denial
of service. This issue only affected Ubuntu 10.04 LTS and Ubuntu 12.04 LTS.
(CVE-2012-3544)

It was discovered that Tomcat incorrectly handled certain authentication
requests. A remote attacker could possibly use this flaw to inject a
request that would get executed with a victim's credentials. This issue
only affected Ubuntu 10.04 LTS, Ubuntu 12.04 LTS, and Ubuntu 12.10.
(CVE-2013-2067)

It was discovered that Tomcat sometimes exposed elements of a previous
request to the current request. This could allow a remote attacker to
possibly obtain sensitive information. This issue only affected Ubuntu
12.10 and Ubuntu 13.04. (CVE-2013-2071)");

  script_tag(name:"affected", value:"'tomcat6, tomcat7' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
