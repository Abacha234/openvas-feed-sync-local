# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71501");
  script_cve_id("CVE-2012-3292");
  script_tag(name:"creation_date", value:"2012-08-10 07:21:12 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2523)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2523");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2523");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'globus-gridftp-server' package(s) announced via the DSA-2523 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the GridFTP component from the Globus Toolkit, a toolkit used for building Grid systems and applications, performed insufficient validation of a name lookup, which could lead to privilege escalation.

For the stable distribution (squeeze), this problem has been fixed in version 3.23-1+squeeze1 of the globus-gridftp-server source package and in version 0.43-1+squeeze1 of the globus-gridftp-server-control source package.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 6.5-1.

We recommend that you upgrade your globus-gridftp-server packages.");

  script_tag(name:"affected", value:"'globus-gridftp-server' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);