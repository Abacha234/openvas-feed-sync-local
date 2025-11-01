# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60106");
  script_cve_id("CVE-2007-3781", "CVE-2007-5969", "CVE-2007-6304");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1451)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1451");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1451");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mysql-dfsg-5.0' package(s) announced via the DSA-1451 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local/remote vulnerabilities have been discovered in the MySQL database server. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3781

It was discovered that the privilege validation for the source table of CREATE TABLE LIKE statements was insufficiently enforced, which might lead to information disclosure. This is only exploitable by authenticated users.

CVE-2007-5969

It was discovered that symbolic links were handled insecurely during the creation of tables with DATA DIRECTORY or INDEX DIRECTORY statements, which might lead to denial of service by overwriting data. This is only exploitable by authenticated users.

CVE-2007-6304

It was discovered that queries to data in a FEDERATED table can lead to a crash of the local database server, if the remote server returns information with less columns than expected, resulting in denial of service.

The old stable distribution (sarge) doesn't contain mysql-dfsg-5.0.

For the stable distribution (etch), these problems have been fixed in version 5.0.32-7etch4.

For the unstable distribution (sid), these problems have been fixed in version 5.0.51-1.

We recommend that you upgrade your mysql-dfsg-5.0 packages.");

  script_tag(name:"affected", value:"'mysql-dfsg-5.0' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);