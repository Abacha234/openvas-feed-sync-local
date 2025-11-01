# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703219");
  script_cve_id("CVE-2015-2788");
  script_tag(name:"creation_date", value:"2015-04-10 22:00:00 +0000 (Fri, 10 Apr 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3219)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3219");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3219");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libdbd-firebird-perl' package(s) announced via the DSA-3219 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Roas discovered a way to cause a buffer overflow in DBD-FireBird, a Perl DBI driver for the Firebird RDBMS, in certain error conditions, due to the use of the sprintf() function to write to a fixed-size memory buffer.

For the stable distribution (wheezy), this problem has been fixed in version 0.91-2+deb7u1.

For the upcoming stable distribution (jessie), this problem has been fixed in version 1.18-2.

For the unstable distribution (sid), this problem has been fixed in version 1.18-2.

We recommend that you upgrade your libdbd-firebird-perl packages.");

  script_tag(name:"affected", value:"'libdbd-firebird-perl' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);