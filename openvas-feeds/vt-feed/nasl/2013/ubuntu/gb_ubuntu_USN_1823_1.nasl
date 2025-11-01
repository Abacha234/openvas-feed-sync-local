# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841428");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0801", "CVE-2013-1669", "CVE-2013-1670", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681");
  script_tag(name:"creation_date", value:"2013-05-17 04:25:07 +0000 (Fri, 17 May 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1823-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1823-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1823-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1178649");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1823-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Thunderbird. If the user
were tricked into opening a specially crafted message with scripting
enabled, an attacker could possibly exploit these to cause a denial of
service via application crash, or potentially execute code with the
privileges of the user invoking Thunderbird. (CVE-2013-0801,
CVE-2013-1669)

Cody Crews discovered that some constructors could be used to bypass
restrictions enforced by their Chrome Object Wrapper (COW). If a user had
scripting enabled, an attacker could exploit this to conduct cross-site
scripting (XSS) attacks. (CVE-2013-1670)

A use-after-free was discovered when resizing video content whilst it is
playing. If a user had scripting enabled, an attacker could potentially
exploit this to execute code with the privileges of the user invoking
Thunderbird. (CVE-2013-1674)

It was discovered that some DOMSVGZoomEvent functions could be used
without being properly initialized, which could lead to information
leakage. (CVE-2013-1675)

Abhishek Arya discovered multiple memory safety issues in Thunderbird. If
the user were tricked into opening a specially crafted message, an
attacker could possibly exploit these to cause a denial of service via
application crash, or potentially execute code with the privileges of
the user invoking Thunderbird. (CVE-2013-1676, CVE-2013-1677,
CVE-2013-1678, CVE-2013-1679, CVE-2013-1680, CVE-2013-1681)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
