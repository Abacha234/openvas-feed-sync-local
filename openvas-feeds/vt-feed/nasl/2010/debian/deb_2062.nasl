# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67634");
  script_cve_id("CVE-2010-1646");
  script_tag(name:"creation_date", value:"2010-07-06 00:35:12 +0000 (Tue, 06 Jul 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2062");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2062");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sudo' package(s) announced via the DSA-2062 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Anders Kaseorg and Evan Broder discovered a vulnerability in sudo, a program designed to allow a sysadmin to give limited root privileges to users, that allows a user with sudo permissions on certain programs to use those programs with an untrusted value of PATH. This could possibly lead to certain intended restrictions being bypassed, such as the secure_path setting.

For the stable distribution (lenny), this problem has been fixed in version 1.6.9p17-3

For the unstable distribution (sid), this problem has been fixed in version 1.7.2p7-1, and will migrate to the testing distribution (squeeze) shortly.

We recommend that you upgrade your sudo package.");

  script_tag(name:"affected", value:"'sudo' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);