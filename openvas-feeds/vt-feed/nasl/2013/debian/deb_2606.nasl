# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702606");
  script_version("2024-11-29T15:40:53+0000");
  script_cve_id("CVE-2012-6095");
  script_name("Debian Security Advisory DSA 2606-1 (proftpd-dfsg - symlink race)");
  script_tag(name:"last_modification", value:"2024-11-29 15:40:53 +0000 (Fri, 29 Nov 2024)");
  script_tag(name:"creation_date", value:"2013-01-13 00:00:00 +0100 (Sun, 13 Jan 2013)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");

  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2606.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_tag(name:"affected", value:"proftpd-dfsg on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (squeeze), this problem has been fixed in
version 1.3.3a-6squeeze6.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.3.4a-3.

We recommend that you upgrade your proftpd-dfsg packages.");
  script_tag(name:"summary", value:"It has been discovered that in ProFTPD, an FTP server, an attacker on
the same physical host as the server may be able to perform a symlink
attack allowing to elevate privileges in some configurations.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
