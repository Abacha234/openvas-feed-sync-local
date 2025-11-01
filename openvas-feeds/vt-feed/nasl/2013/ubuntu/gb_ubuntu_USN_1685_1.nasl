# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841274");
  script_cve_id("CVE-2012-3546", "CVE-2012-4431", "CVE-2012-4534");
  script_tag(name:"creation_date", value:"2013-01-15 12:37:42 +0000 (Tue, 15 Jan 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1685-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1685-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1685-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6, tomcat7' package(s) announced via the USN-1685-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat incorrectly performed certain security
constraint checks in the FORM authenticator. A remote attacker could
possibly use this flaw with a specially-crafted URI to bypass security
constraint checks. This issue only affected Ubuntu 10.04 LTS, Ubuntu 11.10
and Ubuntu 12.04 LTS. (CVE-2012-3546)

It was discovered that Tomcat incorrectly handled requests that lack a
session identifier. A remote attacker could possibly use this flaw to
bypass the cross-site request forgery protection. (CVE-2012-4431)

It was discovered that Tomcat incorrectly handled sendfile and HTTPS when
the NIO connector is used. A remote attacker could use this flaw to cause
Tomcat to stop responding, resulting in a denial of service. This issue
only affected Ubuntu 10.04 LTS, Ubuntu 11.10 and Ubuntu 12.04 LTS.
(CVE-2012-4534)");

  script_tag(name:"affected", value:"'tomcat6, tomcat7' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
