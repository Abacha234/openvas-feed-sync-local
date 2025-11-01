# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703048");
  script_cve_id("CVE-2014-7206");
  script_tag(name:"creation_date", value:"2014-10-07 22:00:00 +0000 (Tue, 07 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3048)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3048");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3048");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apt' package(s) announced via the DSA-3048 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Guillem Jover discovered that the changelog retrieval functionality in apt-get used temporary files in an insecure way, allowing a local user to cause arbitrary files to be overwritten.

This vulnerability is neutralized by the fs.protected_symlinks setting in the Linux kernel, which is enabled by default in Debian 7 Wheezy and up.

For the stable distribution (wheezy), this problem has been fixed in version 0.9.7.9+deb7u6.

For the unstable distribution (sid), this problem has been fixed in version 1.0.9.2.

We recommend that you upgrade your apt packages.");

  script_tag(name:"affected", value:"'apt' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);