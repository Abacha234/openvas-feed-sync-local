# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841791");
  script_cve_id("CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2402", "CVE-2014-2403", "CVE-2014-2412", "CVE-2014-2413", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427");
  script_tag(name:"creation_date", value:"2014-05-05 05:53:19 +0000 (Mon, 05 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2187-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2187-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2187-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1283828");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-2187-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity and availability. An attacker could
exploit these to cause a denial of service or expose sensitive data over
the network. (CVE-2014-0429, CVE-2014-0446, CVE-2014-0451, CVE-2014-0452,
CVE-2014-0454, CVE-2014-0455, CVE-2014-0456, CVE-2014-0457, CVE-2014-0458,
CVE-2014-0461, CVE-2014-2397, CVE-2014-2402, CVE-2014-2412, CVE-2014-2414,
CVE-2014-2421, CVE-2014-2423, CVE-2014-2427)

Two vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit these
to expose sensitive data over the network. (CVE-2014-0453, CVE-2014-0460)

A vulnerability was discovered in the OpenJDK JRE related to availability.
An attacker could exploit this to cause a denial of service.
(CVE-2014-0459)

Jakub Wilk discovered that the OpenJDK JRE incorrectly handled temporary
files. A local attacker could possibly use this issue to overwrite
arbitrary files. In the default installation of Ubuntu, this should be
prevented by the Yama link restrictions. (CVE-2014-1876)

Two vulnerabilities were discovered in the OpenJDK JRE related to data
integrity. (CVE-2014-2398, CVE-2014-2413)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure. An attacker could exploit this to expose sensitive data over
the network. (CVE-2014-2403)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 12.10, Ubuntu 13.10, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
