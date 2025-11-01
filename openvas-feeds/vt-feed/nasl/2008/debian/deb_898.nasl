# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55885");
  script_cve_id("CVE-2005-0870", "CVE-2005-3347", "CVE-2005-3348");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-898)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-898");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-898");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpgroupware' package(s) announced via the DSA-898 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in phpsysinfo, a PHP based host information application that is included in phpgroupware. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-0870

Maksymilian Arciemowicz discovered several cross site scripting problems, of which not all were fixed in DSA 724.

CVE-2005-3347

Christopher Kunz discovered that local variables get overwritten unconditionally and are trusted later, which could lead to the inclusion of arbitrary files.

CVE-2005-3348

Christopher Kunz discovered that user-supplied input is used unsanitised, causing a HTTP Response splitting problem.

For the old stable distribution (woody) these problems have been fixed in version 0.9.14-0.RC3.2.woody5.

For the stable distribution (sarge) these problems have been fixed in version 0.9.16.005-3.sarge4.

For the unstable distribution (sid) these problems have been fixed in version 0.9.16.008-2.

We recommend that you upgrade your phpgroupware packages.");

  script_tag(name:"affected", value:"'phpgroupware' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);