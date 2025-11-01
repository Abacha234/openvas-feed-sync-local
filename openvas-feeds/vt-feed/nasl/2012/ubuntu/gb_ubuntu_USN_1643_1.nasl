# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841232");
  script_cve_id("CVE-2011-2939", "CVE-2011-3597", "CVE-2012-5195", "CVE-2012-5526");
  script_tag(name:"creation_date", value:"2012-12-04 04:18:16 +0000 (Tue, 04 Dec 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1643-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1643-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1643-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the USN-1643-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the decode_xs function in the Encode module is
vulnerable to a heap-based buffer overflow via a crafted Unicode string.
An attacker could use this overflow to cause a denial of service.
(CVE-2011-2939)

It was discovered that the 'new' constructor in the Digest module is
vulnerable to an eval injection. An attacker could use this to execute
arbitrary code. (CVE-2011-3597)

It was discovered that Perl's 'x' string repeat operator is vulnerable
to a heap-based buffer overflow. An attacker could use this to execute
arbitrary code. (CVE-2012-5195)

Ryo Anazawa discovered that the CGI.pm module does not properly escape
newlines in Set-Cookie or P3P (Platform for Privacy Preferences Project)
headers. An attacker could use this to inject arbitrary headers into
responses from applications that use CGI.pm. (CVE-2012-5526)");

  script_tag(name:"affected", value:"'perl' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
