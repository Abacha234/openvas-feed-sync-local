# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840624");
  script_cve_id("CVE-2011-1024", "CVE-2011-1025", "CVE-2011-1081");
  script_tag(name:"creation_date", value:"2011-04-01 13:34:04 +0000 (Fri, 01 Apr 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1100-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1100-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1100-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap, openldap2.3' package(s) announced via the USN-1100-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenLDAP did not properly check forwarded
authentication failures when using a consumer server and chain overlay. If
OpenLDAP were configured in this manner, an attacker could bypass
authentication checks by sending an invalid password to a consumer server.
(CVE-2011-1024)

It was discovered that OpenLDAP did not properly perform authentication
checks to the rootdn when using the back-ndb backend. An attacker could
exploit this to access the directory by sending an arbitrary password.
Ubuntu does not ship OpenLDAP with back-ndb support by default. This issue
did not affect Ubuntu 8.04 LTS. (CVE-2011-1025)

It was discovered that OpenLDAP did not properly validate modrdn requests.
An unauthenticated remote user could use this to cause a denial of service
via application crash. (CVE-2011-1081)");

  script_tag(name:"affected", value:"'openldap, openldap2.3' package(s) on Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
