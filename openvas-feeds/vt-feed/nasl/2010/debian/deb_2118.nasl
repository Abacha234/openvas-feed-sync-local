# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68459");
  script_cve_id("CVE-2010-3315");
  script_tag(name:"creation_date", value:"2010-11-17 02:33:48 +0000 (Wed, 17 Nov 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2118)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2118");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2118");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'subversion' package(s) announced via the DSA-2118 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kamesh Jayachandran and C. Michael Pilat discovered that the mod_dav_svn module of Subversion, a version control system, is not properly enforcing access rules which are scope-limited to named repositories. If the SVNPathAuthz option is set to short_circuit set this may enable an unprivileged attacker to bypass intended access restrictions and disclose or modify repository content.

As a workaround it is also possible to set SVNPathAuthz to on but be advised that this can result in a performance decrease for large repositories.

For the stable distribution (lenny), this problem has been fixed in version 1.5.1dfsg1-5.

For the testing distribution (squeeze), this problem has been fixed in version 1.6.12dfsg-2.

For the unstable distribution (sid), this problem has been fixed in version 1.6.12dfsg-2.

We recommend that you upgrade your subversion packages.");

  script_tag(name:"affected", value:"'subversion' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);