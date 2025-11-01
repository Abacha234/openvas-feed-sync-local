# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842078");
  script_cve_id("CVE-2014-3566", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0400", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412", "CVE-2015-0413");
  script_tag(name:"creation_date", value:"2015-01-28 05:11:16 +0000 (Wed, 28 Jan 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-2487-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2487-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2487-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-2487-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity and availability. An attacker could
exploit these to cause a denial of service or expose sensitive data over
the network. (CVE-2014-3566, CVE-2014-6587, CVE-2014-6601, CVE-2015-0395,
CVE-2015-0408, CVE-2015-0412)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose sensitive
data over the network. (CVE-2014-6585, CVE-2014-6591, CVE-2015-0400,
CVE-2015-0407)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure and integrity. An attacker could exploit this to
expose sensitive data over the network. (CVE-2014-6593)

A vulnerability was discovered in the OpenJDK JRE related to integrity and
availability. An attacker could exploit this to cause a denial of service.
(CVE-2015-0383)

A vulnerability was discovered in the OpenJDK JRE related to availability.
An attacker could this exploit to cause a denial of service.
(CVE-2015-0410)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. (CVE-2015-0413)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
