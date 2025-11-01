# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64168");
  script_cve_id("CVE-2008-3546", "CVE-2008-5516", "CVE-2008-5517", "CVE-2008-5916");
  script_tag(name:"creation_date", value:"2009-06-05 16:04:08 +0000 (Fri, 05 Jun 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-723-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-723-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-723-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'git-core' package(s) announced via the USN-723-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Git did not properly handle long file paths. If a user
were tricked into performing commands on a specially crafted Git repository, an
attacker could possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-3546)

It was discovered that the Git web interface (gitweb) did not correctly handle
shell metacharacters when processing certain commands. A remote attacker could
send specially crafted commands to the Git server and execute arbitrary code
with the privileges of the Git web server. This issue only applied to Ubuntu
7.10 and 8.04 LTS. (CVE-2008-5516, CVE-2008-5517)

It was discovered that the Git web interface (gitweb) did not properly restrict
the diff.external configuration parameter. A local attacker could exploit this
issue and execute arbitrary code with the privileges of the Git web server.
This issue only applied to Ubuntu 8.04 LTS and 8.10. (CVE-2008-5916)");

  script_tag(name:"affected", value:"'git-core' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
