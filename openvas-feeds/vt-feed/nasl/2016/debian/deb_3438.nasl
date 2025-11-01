# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703438");
  script_cve_id("CVE-2015-8025");
  script_tag(name:"creation_date", value:"2016-01-08 23:00:00 +0000 (Fri, 08 Jan 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-3438)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3438");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3438");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xscreensaver' package(s) announced via the DSA-3438 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that unplugging one of the monitors in a multi-monitor setup can cause xscreensaver to crash. Someone with physical access to a machine could use this problem to bypass a locked session.

For the oldstable distribution (wheezy), this problem has been fixed in version 5.15-3+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 5.30-1+deb8u1.

For the testing (stretch) and unstable (sid) distributions, this problem has been fixed in version 5.34-1.

We recommend that you upgrade your xscreensaver packages.");

  script_tag(name:"affected", value:"'xscreensaver' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);