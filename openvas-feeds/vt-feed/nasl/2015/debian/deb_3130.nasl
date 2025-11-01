# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703130");
  script_cve_id("CVE-2014-8990");
  script_tag(name:"creation_date", value:"2015-01-15 23:00:00 +0000 (Thu, 15 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3130)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3130");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3130");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lsyncd' package(s) announced via the DSA-3130 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that lsyncd, a daemon to synchronize local directories using rsync, performed insufficient sanitising of filenames which might result in the execution of arbitrary commands.

For the stable distribution (wheezy), this problem has been fixed in version 2.0.7-3+deb7u1.

For the upcoming stable distribution (jessie), this problem has been fixed in version 2.1.5-2.

For the unstable distribution (sid), this problem has been fixed in version 2.1.5-2.

We recommend that you upgrade your lsyncd packages.");

  script_tag(name:"affected", value:"'lsyncd' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);