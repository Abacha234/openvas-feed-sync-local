# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841319");
  script_cve_id("CVE-2012-5624", "CVE-2012-6093", "CVE-2013-0254");
  script_tag(name:"creation_date", value:"2013-02-15 05:55:30 +0000 (Fri, 15 Feb 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1723-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1723-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1723-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt4-x11' package(s) announced via the USN-1723-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Richard J. Moore and Peter Hartmann discovered that Qt allowed redirecting
requests from http to file schemes. If an attacker were able to perform a
machine-in-the-middle attack, this flaw could be exploited to view sensitive
information. This issue only affected Ubuntu 11.10, Ubuntu 12.04 LTS,
and Ubuntu 12.10. (CVE-2012-5624)

Stephen Cheng discovered that Qt may report incorrect errors when ssl
certificate verification fails. (CVE-2012-6093)

Tim Brown and Mark Lowe discovered that Qt incorrectly used weak
permissions on shared memory segments. A local attacker could use this
issue to view sensitive information, or modify program data belonging to
other users. (CVE-2013-0254)");

  script_tag(name:"affected", value:"'qt4-x11' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
