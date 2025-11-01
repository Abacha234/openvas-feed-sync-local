# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702648");
  script_cve_id("CVE-2012-5529", "CVE-2013-2492");
  script_tag(name:"creation_date", value:"2013-03-14 23:00:00 +0000 (Thu, 14 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2648)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2648");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2648");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firebird2.5' package(s) announced via the DSA-2648 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow was discovered in the Firebird database server, which could result in the execution of arbitrary code. In addition, a denial of service vulnerability was discovered in the TraceManager.

For the stable distribution (squeeze), these problems have been fixed in version 2.5.0.26054~ReleaseCandidate3.ds2-1+squeeze1.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your firebird2.5 packages.");

  script_tag(name:"affected", value:"'firebird2.5' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);