# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56276");
  script_cve_id("CVE-2005-4189");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-970)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-970");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-970");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kronolith' package(s) announced via the DSA-970 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Johannes Greil of SEC Consult discovered several cross-site scripting vulnerabilities in kronolith, the Horde calendar application.

The old stable distribution (woody) does not contain kronolith packages.

For the stable distribution (sarge) these problems have been fixed in version 1.1.4-2sarge1.

For the unstable distribution (sid) these problems have been fixed in version 2.0.6-1 of kronolith2.

We recommend that you upgrade your kronolith and kronolith2 packages.");

  script_tag(name:"affected", value:"'kronolith' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);