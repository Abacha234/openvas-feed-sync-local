# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840574");
  script_cve_id("CVE-2010-4172");
  script_tag(name:"creation_date", value:"2011-01-31 14:15:14 +0000 (Mon, 31 Jan 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1048-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1048-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1048-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6' package(s) announced via the USN-1048-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Tomcat did not properly escape certain parameters in
the Manager application which could result in browsers becoming vulnerable
to cross-site scripting attacks when processing the output. With cross-site
scripting vulnerabilities, if a user were tricked into viewing server
output during a crafted server request, a remote attacker could exploit
this to modify the contents, or steal confidential data (such as
passwords), within the same domain.");

  script_tag(name:"affected", value:"'tomcat6' package(s) on Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
