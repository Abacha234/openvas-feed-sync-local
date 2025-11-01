# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842398");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_tag(name:"creation_date", value:"2015-07-31 05:22:57 +0000 (Fri, 31 Jul 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-2696-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2696-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2696-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/LogJam");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-2696-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity, and availability. An attacker
could exploit these to cause a denial of service or expose sensitive
data over the network. (CVE-2015-2590, CVE-2015-2628, CVE-2015-4731,
CVE-2015-4732, CVE-2015-4733, CVE-2015-4760, CVE-2015-4748)

Several vulnerabilities were discovered in the cryptographic components
of the OpenJDK JRE. An attacker could exploit these to expose sensitive
data over the network. (CVE-2015-2601, CVE-2015-2808, CVE-2015-4000,
CVE-2015-2625, CVE-2015-2613)

As a security improvement, this update modifies OpenJDK behavior to
disable RC4 TLS/SSL cipher suites by default.

As a security improvement, this update modifies OpenJDK behavior to
reject DH key sizes below 768 bits by default, preventing a possible
downgrade attack.

Several vulnerabilities were discovered in the OpenJDK JRE related
to information disclosure. An attacker could exploit these to expose
sensitive data over the network. (CVE-2015-2621, CVE-2015-2632)

A vulnerability was discovered with how the JNDI component of the
OpenJDK JRE handles DNS resolutions. A remote attacker could exploit
this to cause a denial of service. (CVE-2015-4749)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 14.04, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
