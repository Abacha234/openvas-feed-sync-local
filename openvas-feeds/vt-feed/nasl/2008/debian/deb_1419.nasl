# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.59954");
  script_cve_id("CVE-2007-4575");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1419)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1419");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1419");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'hsqldb, openoffice.org' package(s) announced via the DSA-1419 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been discovered in HSQLDB, the default database engine shipped with OpenOffice.org. This could result in the execution of arbitrary Java code embedded in a OpenOffice.org database document with the user's privilege. This update requires an update of both openoffice.org and hsqldb.

The old stable distribution (sarge) is not affected by this problem.

For the stable distribution (etch) this problem has been fixed in version 2.0.4.dfsg.2-7etch4 of OpenOffice.org and in version 1.8.0.7-1etch1 of hsqldb.

For the unstable distribution (sid) this problem has been fixed in version 2.3.1-1 of OpenOffice.org and in version 1.8.0.9-2 of hsqldb.

For the experimental distribution this problem has been fixed in version 2.3.1~rc1-1 of OpenOffice.org and in version 1.8.0.9-1 of hsqldb.

We recommend that you upgrade your OpenOffice.org and hsqldb packages.");

  script_tag(name:"affected", value:"'hsqldb, openoffice.org' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);