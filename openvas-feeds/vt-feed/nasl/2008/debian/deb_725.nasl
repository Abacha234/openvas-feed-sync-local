# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53991");
  script_cve_id("CVE-2005-0392");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-725)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-725");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-725");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ppxp' package(s) announced via the DSA-725 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jens Steube discovered that ppxp, yet another PPP program, does not release root privileges when opening potentially user supplied log files. This can be tricked into opening a root shell.

For the old stable distribution (woody) this problem has been fixed in version 0.2001080415-6woody2 (DSA 725-1).

For the stable distribution (sarge) this problem has been fixed in version 0.2001080415-10sarge2.

For the unstable distribution (sid) this problem has been fixed in version 0.2001080415-11.

We recommend that you upgrade your ppxp package.");

  script_tag(name:"affected", value:"'ppxp' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);