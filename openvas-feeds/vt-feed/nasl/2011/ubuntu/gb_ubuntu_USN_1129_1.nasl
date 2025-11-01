# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840647");
  script_cve_id("CVE-2010-1168", "CVE-2010-1447", "CVE-2010-2761", "CVE-2010-4410", "CVE-2010-4411", "CVE-2011-1487");
  script_tag(name:"creation_date", value:"2011-05-10 12:04:15 +0000 (Tue, 10 May 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1129-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1129-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1129-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the USN-1129-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Safe.pm Perl module incorrectly handled
Safe::reval and Safe::rdo access restrictions. An attacker could use this
flaw to bypass intended restrictions and possibly execute arbitrary code.
(CVE-2010-1168, CVE-2010-1447)

It was discovered that the CGI.pm Perl module incorrectly handled certain
MIME boundary strings. An attacker could use this flaw to inject arbitrary
HTTP headers and perform HTTP response splitting and cross-site scripting
attacks. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 10.04 LTS and
10.10. (CVE-2010-2761, CVE-2010-4411)

It was discovered that the CGI.pm Perl module incorrectly handled newline
characters. An attacker could use this flaw to inject arbitrary HTTP
headers and perform HTTP response splitting and cross-site scripting
attacks. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 10.04 LTS and
10.10. (CVE-2010-4410)

It was discovered that the lc, lcfirst, uc, and ucfirst functions did not
properly apply the taint attribute when processing tainted input. An
attacker could use this flaw to bypass intended restrictions. This issue
only affected Ubuntu 8.04 LTS, 10.04 LTS and 10.10. (CVE-2011-1487)");

  script_tag(name:"affected", value:"'perl' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
