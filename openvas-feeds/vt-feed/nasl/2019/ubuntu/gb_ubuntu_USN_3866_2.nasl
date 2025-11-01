# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843912");
  script_tag(name:"creation_date", value:"2019-02-22 03:07:33 +0000 (Fri, 22 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3866-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3866-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3866-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1815339");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the USN-3866-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3866-1 fixed vulnerabilities in Ghostscript. The new Ghostscript
version introduced a regression when printing certain page sizes. This
update fixes the problem.

Original advisory details:

 Tavis Ormandy discovered that Ghostscript incorrectly handled certain
 PostScript files. If a user or automated system were tricked into
 processing a specially crafted file, a remote attacker could possibly use
 this issue to access arbitrary files, execute arbitrary code, or cause a
 denial of service.");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
