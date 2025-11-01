# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67830");
  script_cve_id("CVE-2009-4896");
  script_tag(name:"creation_date", value:"2010-08-21 06:54:16 +0000 (Sat, 21 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2073)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2073");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2073");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mlmmj' package(s) announced via the DSA-2073 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Streibelt reported a directory traversal flaw in the way the Mailing List Managing Made Joyful mailing list manager processed users' requests originating from the administrator web interface without enough input validation. A remote, authenticated attacker could use these flaws to write and/or delete arbitrary files.

For the stable distribution (lenny), these problems have been fixed in version 1.2.15-1.1+lenny1.

For the unstable distribution (sid), these problems have been fixed in version 1.2.17-1.1.

We recommend that you upgrade your mlmmj package.");

  script_tag(name:"affected", value:"'mlmmj' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);