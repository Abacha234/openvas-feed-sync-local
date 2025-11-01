# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703274");
  script_cve_id("CVE-2015-3456");
  script_tag(name:"creation_date", value:"2015-05-27 22:00:00 +0000 (Wed, 27 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3274)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3274");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3274");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'virtualbox' package(s) announced via the DSA-3274 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jason Geffner discovered a buffer overflow in the emulated floppy disk drive, resulting in potential privilege escalation.

For the oldstable distribution (wheezy), this problem has been fixed in version 4.1.18-dfsg-2+deb7u5.

For the stable distribution (jessie), this problem has been fixed in version 4.3.18-dfsg-3+deb8u2.

For the unstable distribution (sid), this problem has been fixed in version 4.3.28-dfsg-1.

We recommend that you upgrade your virtualbox packages.");

  script_tag(name:"affected", value:"'virtualbox' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);