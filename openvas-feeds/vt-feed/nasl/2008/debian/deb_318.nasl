# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53607");
  script_cve_id("CVE-2003-0366");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-318)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-318");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-318");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lyskom-server' package(s) announced via the DSA-318 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Calle Dybedahl discovered a bug in lyskom-server which could result in a denial of service where an unauthenticated user could cause the server to become unresponsive as it processes a large query.

For the stable distribution (woody) this problem has been fixed in version 2.0.6-1woody1.

The old stable distribution (potato) does not contain a lyskom-server package.

For the unstable distribution (sid) this problem is fixed in version 2.0.7-2.

We recommend that you update your lyskom-server package.");

  script_tag(name:"affected", value:"'lyskom-server' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);