# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703248");
  script_cve_id("CVE-2008-7313", "CVE-2014-5008");
  script_tag(name:"creation_date", value:"2015-05-01 22:00:00 +0000 (Fri, 01 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-04 16:57:00 +0000 (Tue, 04 Apr 2017)");

  script_name("Debian: Security Advisory (DSA-3248)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3248");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3248");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libphp-snoopy' package(s) announced via the DSA-3248 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that missing input saniting in Snoopy, a PHP class that simulates a web browser may result in the execution of arbitrary commands.

For the oldstable distribution (wheezy), this problem has been fixed in version 2.0.0-1~deb7u1.

For the stable distribution (jessie), this problem was fixed before the initial release.

For the unstable distribution (sid), this problem has been fixed in version 2.0.0-1.

We recommend that you upgrade your libphp-snoopy packages.");

  script_tag(name:"affected", value:"'libphp-snoopy' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);