# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841227");
  script_cve_id("CVE-2012-3426", "CVE-2012-5563", "CVE-2012-5571");
  script_tag(name:"creation_date", value:"2012-11-29 04:10:15 +0000 (Thu, 29 Nov 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1641-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1641-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1641-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keystone' package(s) announced via the USN-1641-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vijaya Erukala discovered that Keystone did not properly invalidate
EC2-style credentials such that if credentials were removed from a tenant,
an authenticated and authorized user using those credentials may still be
allowed access beyond the account owner's expectations. (CVE-2012-5571)

It was discovered that Keystone did not properly implement token
expiration. A remote attacker could use this to continue to access an
account that is disabled or has a changed password. This issue was
previously fixed as CVE-2012-3426 but was reintroduced in Ubuntu 12.10.
(CVE-2012-5563)");

  script_tag(name:"affected", value:"'keystone' package(s) on Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
