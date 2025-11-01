# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703384");
  script_cve_id("CVE-2015-4813", "CVE-2015-4896");
  script_tag(name:"creation_date", value:"2015-10-28 23:00:00 +0000 (Wed, 28 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3384)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3384");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3384");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'virtualbox' package(s) announced via the DSA-3384 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in VirtualBox, an x86 virtualisation solution.

For the oldstable distribution (wheezy), these problems have been fixed in version 4.1.42-dfsg-1+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 4.3.32-dfsg-1+deb8u2.

For the testing distribution (stretch), these problems have been fixed in version 5.0.8-dfsg-1.

For the unstable distribution (sid), these problems have been fixed in version 5.0.8-dfsg-1.

We recommend that you upgrade your virtualbox packages.");

  script_tag(name:"affected", value:"'virtualbox' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);