# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72625");
  script_cve_id("CVE-2012-2251", "CVE-2012-2252");
  script_tag(name:"creation_date", value:"2012-12-04 16:42:07 +0000 (Tue, 04 Dec 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2578)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2578");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2578");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rssh' package(s) announced via the DSA-2578 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"James Clawson discovered that rssh, a restricted shell for OpenSSH to be used with scp, sftp, rdist and cvs, was not correctly filtering command line options. This could be used to force the execution of a remote script and thus allow arbitrary command execution. Two CVE were assigned:

CVE-2012-2251

Incorrect filtering of command line when using rsync protocol. It was for example possible to pass dangerous options after a -- switch. The rsync protocol support has been added in a Debian (and Fedora/Red Hat) specific patch, so this vulnerability doesn't affect upstream.

CVE-2012-2252

Incorrect filtering of the --rsh option: the filter preventing usage of the --rsh= option would not prevent passing --rsh. This vulnerability affects upstream code.

For the stable distribution (squeeze), this problem has been fixed in version 2.3.2-13squeeze3.

For the testing distribution (wheezy), this problem has been fixed in version 2.3.3-6.

For the unstable distribution (sid), this problem has been fixed in version 2.3.3-6.

We recommend that you upgrade your rssh packages.");

  script_tag(name:"affected", value:"'rssh' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);