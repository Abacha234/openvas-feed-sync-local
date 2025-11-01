# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842630");
  script_cve_id("CVE-2015-7575", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_tag(name:"creation_date", value:"2016-02-05 07:44:38 +0000 (Fri, 05 Feb 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-2884-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2884-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2884-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-2884-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in the OpenJDK JRE related
to information disclosure, data integrity, and availability. An
attacker could exploit these to cause a denial of service, expose
sensitive data over the network, or possibly execute arbitrary code.
(CVE-2016-0483, CVE-2016-0494)

A vulnerability was discovered in the OpenJDK JRE related to data
integrity. An attacker could exploit this to expose sensitive data
over the network or possibly execute arbitrary code. (CVE-2016-0402)

It was discovered that OpenJDK 7 incorrectly allowed MD5 to be used
for TLS connections. If a remote attacker were able to perform a
machine-in-the-middle attack, this flaw could be exploited to expose
sensitive information. (CVE-2015-7575)

A vulnerability was discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit this to expose
sensitive data over the network. (CVE-2016-0448)

A vulnerability was discovered in the OpenJDK JRE related to
availability. An attacker could exploit this to cause a denial of
service. (CVE-2016-0466)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
