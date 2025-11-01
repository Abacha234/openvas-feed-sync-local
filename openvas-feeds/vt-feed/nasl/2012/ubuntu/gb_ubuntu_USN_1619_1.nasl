# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841202");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-1531", "CVE-2012-1532", "CVE-2012-1533", "CVE-2012-3143", "CVE-2012-3159", "CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5067", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5070", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5074", "CVE-2012-5075", "CVE-2012-5076", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5087", "CVE-2012-5088", "CVE-2012-5089");
  script_tag(name:"creation_date", value:"2012-10-29 05:33:54 +0000 (Mon, 29 Oct 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1619-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1619-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1619-1");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6, openjdk-7' package(s) announced via the USN-1619-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several information disclosure vulnerabilities were discovered in the
OpenJDK JRE. (CVE-2012-3216, CVE-2012-5069, CVE-2012-5072, CVE-2012-5075,
CVE-2012-5077, CVE-2012-5085)

Vulnerabilities were discovered in the OpenJDK JRE related to information
disclosure and data integrity. (CVE-2012-4416, CVE-2012-5071)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit these
to cause a denial of service. (CVE-2012-1531, CVE-2012-1532, CVE-2012-1533,
CVE-2012-3143, CVE-2012-3159, CVE-2012-5068, CVE-2012-5083, CVE-2012-5084,
CVE-2012-5086, CVE-2012-5089)

Information disclosure vulnerabilities were discovered in the OpenJDK JRE.
These issues only affected Ubuntu 12.10. (CVE-2012-5067, CVE-2012-5070)

Vulnerabilities were discovered in the OpenJDK JRE related to data
integrity. (CVE-2012-5073, CVE-2012-5079)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure and data integrity. This issue only affected Ubuntu 12.10.
(CVE-2012-5074)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit these
to cause a denial of service. These issues only affected Ubuntu 12.10.
(CVE-2012-5076, CVE-2012-5087, CVE-2012-5088)

A denial of service vulnerability was found in OpenJDK. (CVE-2012-5081)

Please see the following for more information:
[link moved to references]");

  script_tag(name:"affected", value:"'openjdk-6, openjdk-7' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
