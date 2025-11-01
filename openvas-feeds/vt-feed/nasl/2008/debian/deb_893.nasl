# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55874");
  script_cve_id("CVE-2005-3325");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-893)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-893");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-893");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'acidlab' package(s) announced via the DSA-893 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Remco Verhoef has discovered a vulnerability in acidlab, Analysis Console for Intrusion Databases, and in acidbase, Basic Analysis and Security Engine, which can be exploited by malicious users to conduct SQL injection attacks.

The maintainers of Analysis Console for Intrusion Databases (ACID) in Debian, of which BASE is a fork off, after a security audit of both BASE and ACID have determined that the flaw found not only affected the base_qry_main.php (in BASE) or acid_qry_main.php (in ACID) component but was also found in other elements of the consoles due to improper parameter validation and filtering.

All the SQL injection bugs and Cross Site Scripting bugs found have been fixed in the Debian package, closing all the different attack vectors detected.

For the old stable distribution (woody) this problem has been fixed in version 0.9.6b20-2.1.

For the stable distribution (sarge) this problem has been fixed in version 0.9.6b20-10.1.

For the unstable distribution (sid) this problem has been fixed in version 0.9.6b20-13 and in version 1.2.1-1 of acidbase.

We recommend that you upgrade your acidlab and acidbase package.");

  script_tag(name:"affected", value:"'acidlab' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);