# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70408");
  script_cve_id("CVE-2011-1485");
  script_tag(name:"creation_date", value:"2011-10-16 21:01:53 +0000 (Sun, 16 Oct 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2319)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2319");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2319");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'policykit-1' package(s) announced via the DSA-2319 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Neel Mehta discovered that a race condition in Policykit, a framework for managing administrative policies and privileges, allowed local users to elevate privileges by executing a setuid program from pkexec.

The oldstable distribution (lenny) does not contain the policykit-1 package.

For the stable distribution (squeeze), this problem has been fixed in version 0.96-4+squeeze1.

For the testing distribution (wheezy) and unstable distribution (sid), this problem has been fixed in version 0.101-4.

We recommend that you upgrade your policykit-1 packages.");

  script_tag(name:"affected", value:"'policykit-1' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);