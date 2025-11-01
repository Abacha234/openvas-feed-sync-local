# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840433");
  script_cve_id("CVE-2007-5902", "CVE-2007-5971", "CVE-2007-5972", "CVE-2010-1320", "CVE-2010-1321");
  script_tag(name:"creation_date", value:"2010-05-28 08:00:59 +0000 (Fri, 28 May 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-940-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-940-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-940-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the USN-940-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Kerberos did not correctly free memory in the
GSSAPI and kdb libraries. If a remote attacker were able to manipulate
an application using these libraries carefully, the service could
crash, leading to a denial of service. (Only Ubuntu 6.06 LTS was
affected.) (CVE-2007-5902, CVE-2007-5971, CVE-2007-5972)

Joel Johnson, Brian Almeida, and Shawn Emery discovered that Kerberos
did not correctly verify certain packet structures. An unauthenticated
remote attacker could send specially crafted traffic to cause the KDC or
kadmind services to crash, leading to a denial of service. (CVE-2010-1320,
CVE-2010-1321)");

  script_tag(name:"affected", value:"'krb5' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
