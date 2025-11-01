# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703266");
  script_cve_id("CVE-2015-3202");
  script_tag(name:"creation_date", value:"2015-05-20 22:00:00 +0000 (Wed, 20 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3266)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3266");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3266");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fuse' package(s) announced via the DSA-3266 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered that FUSE, a Filesystem in USErspace, does not scrub the environment before executing mount or umount with elevated privileges. A local user can take advantage of this flaw to overwrite arbitrary files and gain elevated privileges by accessing debugging features via the environment that would not normally be safe for unprivileged users.

For the oldstable distribution (wheezy), this problem has been fixed in version 2.9.0-2+deb7u2.

For the stable distribution (jessie), this problem has been fixed in version 2.9.3-15+deb8u1.

For the testing distribution (stretch) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your fuse packages.");

  script_tag(name:"affected", value:"'fuse' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);