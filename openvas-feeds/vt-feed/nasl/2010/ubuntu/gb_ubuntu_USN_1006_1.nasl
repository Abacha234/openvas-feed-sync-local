# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840517");
  script_tag(name:"creation_date", value:"2010-10-22 14:42:09 +0000 (Fri, 22 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1006-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1006-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1006-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/660075");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit' package(s) announced via the USN-1006-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A large number of security issues were discovered in the WebKit browser and
JavaScript engines. If a user were tricked into viewing a malicious
website, a remote attacker could exploit a variety of issues related to web
browser security, including cross-site scripting attacks, denial of
service attacks, and arbitrary code execution.

Please consult the bug listed at the top of this advisory to get the exact
list of CVE numbers fixed for each release.");

  script_tag(name:"affected", value:"'webkit' package(s) on Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
