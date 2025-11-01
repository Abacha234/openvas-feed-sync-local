# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702997");
  script_cve_id("CVE-2014-0479");
  script_tag(name:"creation_date", value:"2014-08-04 22:00:00 +0000 (Mon, 04 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2997)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2997");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2997");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'reportbug' package(s) announced via the DSA-2997 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Wilk discovered a remote command execution flaw in reportbug, a tool to report bugs in the Debian distribution. A man-in-the-middle attacker could put shell metacharacters in the version number allowing arbitrary code execution with the privileges of the user running reportbug.

For the stable distribution (wheezy), this problem has been fixed in version 6.4.4+deb7u1.

For the testing distribution (jessie), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 6.5.0+nmu1.

We recommend that you upgrade your reportbug packages.");

  script_tag(name:"affected", value:"'reportbug' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);