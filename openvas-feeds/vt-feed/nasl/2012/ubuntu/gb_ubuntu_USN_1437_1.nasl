# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841002");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-1823", "CVE-2012-2311");
  script_tag(name:"creation_date", value:"2012-05-08 07:07:35 +0000 (Tue, 08 May 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1437-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1437-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1437-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-1437-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP, when used as a stand alone CGI processor
for the Apache Web Server, did not properly parse and filter query
strings. This could allow a remote attacker to execute arbitrary code
running with the privilege of the web server. Configurations using
mod_php5 and FastCGI were not vulnerable.

This update addresses the issue when the PHP CGI interpreter
is configured using mod_cgi and mod_actions as described in
/usr/share/doc/php5-cgi/README.Debian.gz, however, if an alternate
configuration is used to enable PHP CGI processing, it should be
reviewed to ensure that command line arguments cannot be passed to
the PHP interpreter. Please see CVE-2012-2311 for more details and
potential mitigation approaches.");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
