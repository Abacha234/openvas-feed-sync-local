# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53323");
  script_cve_id("CVE-2003-0057");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-248)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-248");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-248");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'hypermail' package(s) announced via the DSA-248 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ulf Harnhammar discovered two problems in hypermail, a program to create HTML archives of mailing lists.

An attacker could craft a long filename for an attachment that would overflow two buffers when a certain option for interactive use was given, opening the possibility to inject arbitrary code. This code would then be executed under the user id hypermail runs as, mostly as a local user. Automatic and silent use of hypermail does not seem to be affected.

The CGI program mail, which is not installed by the Debian package, does a reverse look-up of the user's IP number and copies the resulting hostname into a fixed-size buffer. A specially crafted DNS reply could overflow this buffer, opening the program to an exploit.

For the stable distribution (woody) this problem has been fixed in version 2.1.3-2.0.

For the old stable distribution (potato) this problem has been fixed in version 2.0b25-1.1.

For the unstable distribution (sid) this problem has been fixed in version 2.1.6-1.

We recommend that you upgrade your hypermail packages.");

  script_tag(name:"affected", value:"'hypermail' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);