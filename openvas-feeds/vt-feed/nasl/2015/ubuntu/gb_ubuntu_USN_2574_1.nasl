# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842172");
  script_cve_id("CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488");
  script_tag(name:"creation_date", value:"2015-04-22 05:23:01 +0000 (Wed, 22 Apr 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2574-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2574-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2574-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-2574-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity and availability. An attacker
could exploit these to cause a denial of service or expose sensitive
data over the network. (CVE-2015-0460, CVE-2015-0469)

Alexander Cherepanov discovered that OpenJDK JRE was vulnerable to
directory traversal issues with respect to handling jar files. An
attacker could use this to expose sensitive data. (CVE-2015-0480)

Florian Weimer discovered that the RSA implementation in the JCE
component in OpenJDK JRE did not follow recommended practices for
implementing RSA signatures. An attacker could use this to expose
sensitive data. (CVE-2015-0478)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. An attacker could exploit this expose sensitive data over
the network. (CVE-2015-0477)

A vulnerability was discovered in the OpenJDK JRE related to
availability. An attacker could exploit these to cause a denial
of service. (CVE-2015-0488)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
