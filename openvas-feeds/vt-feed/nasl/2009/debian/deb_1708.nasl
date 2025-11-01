# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63222");
  script_cve_id("CVE-2008-5516", "CVE-2008-5517", "CVE-2008-5916");
  script_tag(name:"creation_date", value:"2009-01-20 21:42:09 +0000 (Tue, 20 Jan 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1708)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1708");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1708");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'git-core' package(s) announced via the DSA-1708 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that gitweb, the web interface for the Git version control system, contained several vulnerabilities:

Remote attackers could use crafted requests to execute shell commands on the web server, using the snapshot generation and pickaxe search functionality (CVE-2008-5916).

Local users with write access to the configuration of a Git repository served by gitweb could cause gitweb to execute arbitrary shell commands with the permission of the web server (CVE-2008-5516, CVE-2008-5517).

For the stable distribution (etch), these problems have been fixed in version 1.4.4.4-4+etch1.

For the unstable distribution (sid) and testing distribution (lenny), the remote shell command injection issue (CVE-2008-5516) has been fixed in version 1.5.6-1. The other issue will be fixed soon.

We recommend that you upgrade your Git packages.");

  script_tag(name:"affected", value:"'git-core' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);