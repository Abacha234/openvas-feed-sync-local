# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71145");
  script_cve_id("CVE-2012-0869", "CVE-2012-1293");
  script_tag(name:"creation_date", value:"2012-03-12 15:31:57 +0000 (Mon, 12 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2414)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2414");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2414");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fex' package(s) announced via the DSA-2414 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nicola Fioravanti discovered that F*X, a web service for transferring very large files, is not properly sanitizing input parameters of the fup script. An attacker can use this flaw to conduct reflected cross-site scripting attacks via various script parameters.

For the stable distribution (squeeze), this problem has been fixed in version 20100208+debian1-1+squeeze3.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 20120215-1.

We recommend that you upgrade your fex packages.");

  script_tag(name:"affected", value:"'fex' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);