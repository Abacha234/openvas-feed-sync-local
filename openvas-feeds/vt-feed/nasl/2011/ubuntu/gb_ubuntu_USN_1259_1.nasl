# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840798");
  script_cve_id("CVE-2011-1176", "CVE-2011-3348", "CVE-2011-3368");
  script_tag(name:"creation_date", value:"2011-11-11 04:25:23 +0000 (Fri, 11 Nov 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1259-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1259-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1259-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2, apache2-mpm-itk' package(s) announced via the USN-1259-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the mod_proxy module in Apache did not properly
interact with the RewriteRule and ProxyPassMatch pattern matches
in the configuration of a reverse proxy. This could allow remote
attackers to contact internal webservers behind the proxy that were
not intended for external exposure. (CVE-2011-3368)

Stefano Nichele discovered that the mod_proxy_ajp module in Apache when
used with mod_proxy_balancer in certain configurations could allow
remote attackers to cause a denial of service via a malformed HTTP
request. (CVE-2011-3348)

Samuel Montosa discovered that the ITK Multi-Processing Module for
Apache did not properly handle certain configuration sections that
specify NiceValue but not AssignUserID, preventing Apache from dropping
privileges correctly. This issue only affected Ubuntu 10.04 LTS, Ubuntu
10.10 and Ubuntu 11.04. (CVE-2011-1176)

USN 1199-1 fixed a vulnerability in the byterange filter of Apache. The
upstream patch introduced a regression in Apache when handling specific
byte range requests. This update fixes the issue.

Original advisory details:

 A flaw was discovered in the byterange filter in Apache. A remote attacker
 could exploit this to cause a denial of service via resource exhaustion.");

  script_tag(name:"affected", value:"'apache2, apache2-mpm-itk' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
