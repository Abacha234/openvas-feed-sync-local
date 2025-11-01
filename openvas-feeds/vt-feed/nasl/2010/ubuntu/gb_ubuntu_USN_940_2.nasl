# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840462");
  script_cve_id("CVE-2010-1320", "CVE-2010-1321");
  script_tag(name:"creation_date", value:"2010-07-23 14:10:25 +0000 (Fri, 23 Jul 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-940-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-940-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-940-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-940-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-940-1 fixed vulnerabilities in Kerberos. This update provides the
corresponding updates for Ubuntu 10.04.

Original advisory details:

 Joel Johnson, Brian Almeida, and Shawn Emery discovered that Kerberos
 did not correctly verify certain packet structures. An unauthenticated
 remote attacker could send specially crafted traffic to cause the KDC or
 kadmind services to crash, leading to a denial of service. (CVE-2010-1320,
 CVE-2010-1321)");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
