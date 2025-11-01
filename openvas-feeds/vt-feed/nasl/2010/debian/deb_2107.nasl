# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68087");
  script_cve_id("CVE-2010-2953");
  script_tag(name:"creation_date", value:"2010-10-10 17:35:00 +0000 (Sun, 10 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2107)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2107");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2107");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'couchdb' package(s) announced via the DSA-2107 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that in couchdb, a distributed, fault-tolerant and schema-free document-oriented database, an insecure library search path is used. A local attacker could execute arbitrary code by first dumping a maliciously crafted shared library in some directory, and then having an administrator run couchdb from this same directory.

For the stable distribution (lenny), this problem has been fixed in version 0.8.0-2+lenny1.

We recommend that you upgrade your couchdb package.");

  script_tag(name:"affected", value:"'couchdb' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);