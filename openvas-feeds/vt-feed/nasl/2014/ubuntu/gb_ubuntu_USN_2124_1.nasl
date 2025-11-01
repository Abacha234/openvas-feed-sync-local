# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841732");
  script_cve_id("CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5896", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376", "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0428");
  script_tag(name:"creation_date", value:"2014-03-04 05:19:25 +0000 (Tue, 04 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2124-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2124-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2124-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1283828");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6' package(s) announced via the USN-2124-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in the OpenJDK JRE related to information
disclosure and data integrity. An attacker could exploit this to expose
sensitive data over the network. (CVE-2014-0411)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity and availability. An attacker could
exploit these to cause a denial of service or expose sensitive data over
the network. (CVE-2013-5878, CVE-2013-5907, CVE-2014-0373, CVE-2014-0422,
CVE-2014-0428)

Two vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose sensitive
data over the network. (CVE-2013-5884, CVE-2014-0368)

Two vulnerabilities were discovered in the OpenJDK JRE related to
availability. An attacker could exploit these to cause a denial of service.
(CVE-2013-5896, CVE-2013-5910)

Two vulnerabilities were discovered in the OpenJDK JRE related to data
integrity. (CVE-2014-0376, CVE-2014-0416)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure and availability. An attacker could exploit this to expose
sensitive data over the network or cause a denial of service.
(CVE-2014-0423)

In addition to the above, USN-2033-1 fixed several vulnerabilities and bugs
in OpenJDK 6. This update introduced a regression which caused an exception
condition in javax.xml when instantiating encryption algorithms. This
update fixes the problem. We apologize for the inconvenience.");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Ubuntu 10.04, Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
