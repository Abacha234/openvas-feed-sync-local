# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842957");
  script_cve_id("CVE-2016-0772", "CVE-2016-1000110", "CVE-2016-5636", "CVE-2016-5699");
  script_tag(name:"creation_date", value:"2016-11-23 04:39:13 +0000 (Wed, 23 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-09 11:29:00 +0000 (Sat, 09 Feb 2019)");

  script_name("Ubuntu: Security Advisory (USN-3134-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3134-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3134-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7, python3.2, python3.4, python3.5' package(s) announced via the USN-3134-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the smtplib library in Python did not return an
error when StartTLS fails. A remote attacker could possibly use this to
expose sensitive information. (CVE-2016-0772)

Remi Rampin discovered that Python would not protect CGI applications
from contents of the HTTP_PROXY environment variable when based on
the contents of the Proxy header from HTTP requests. A remote attacker
could possibly use this to cause a CGI application to redirect outgoing
HTTP requests. (CVE-2016-1000110)

Insu Yun discovered an integer overflow in the zipimporter module in
Python that could lead to a heap-based overflow. An attacker could
use this to craft a special zip file that when read by Python could
possibly execute arbitrary code. (CVE-2016-5636)

Guido Vranken discovered that the urllib modules in Python did
not properly handle carriage return line feed (CRLF) in headers. A
remote attacker could use this to craft URLs that inject arbitrary
HTTP headers. This issue only affected Ubuntu 12.04 LTS and Ubuntu
14.04 LTS. (CVE-2016-5699)");

  script_tag(name:"affected", value:"'python2.7, python3.2, python3.4, python3.5' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
