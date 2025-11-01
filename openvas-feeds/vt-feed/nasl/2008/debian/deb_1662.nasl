# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61852");
  script_cve_id("CVE-2008-4098");
  script_tag(name:"creation_date", value:"2008-11-19 15:52:57 +0000 (Wed, 19 Nov 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1662)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1662");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1662");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg-5.0' package(s) announced via the DSA-1662 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A symlink traversal vulnerability was discovered in MySQL, a relational database server. The weakness could permit an attacker having both CREATE TABLE access to a database and the ability to execute shell commands on the database server to bypass MySQL access controls, enabling them to write to tables in databases to which they would not ordinarily have access.

The Common Vulnerabilities and Exposures project identifies this vulnerability as CVE-2008-4098. Note that a closely aligned issue, identified as CVE-2008-4097, was prevented by the update announced in DSA-1608-1. This new update supersedes that fix and mitigates both potential attack vectors.

For the stable distribution (etch), this problem has been fixed in version 5.0.32-7etch8.

We recommend that you upgrade your mysql packages.");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);