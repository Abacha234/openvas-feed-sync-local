# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55886");
  script_cve_id("CVE-2005-0870", "CVE-2005-2600", "CVE-2005-3347", "CVE-2005-3348");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-899)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-899");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-899");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'egroupware' package(s) announced via the DSA-899 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in egroupware, a web-based groupware suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-0870

Maksymilian Arciemowicz discovered several cross site scripting problems in phpsysinfo, which are also present in the imported version in egroupware and of which not all were fixed in DSA 724.

CVE-2005-2600

Alexander Heidenreich discovered a cross-site scripting problem in the tree view of FUD Forum Bulletin Board Software, which is also present in egroupware and allows remote attackers to read private posts via a modified mid parameter.

CVE-2005-3347

Christopher Kunz discovered that local variables get overwritten unconditionally in phpsysinfo, which are also present in egroupware, and are trusted later, which could lead to the inclusion of arbitrary files.

CVE-2005-3348

Christopher Kunz discovered that user-supplied input is used unsanitised in phpsysinfo and imported in egroupware, causing a HTTP Response splitting problem.

The old stable distribution (woody) does not contain egroupware packages.

For the stable distribution (sarge) this problem has been fixed in version 1.0.0.007-2.dfsg-2sarge4.

For the unstable distribution (sid) this problem has been fixed in version 1.0.0.009.dfsg-3-3.

We recommend that you upgrade your egroupware packages.");

  script_tag(name:"affected", value:"'egroupware' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);