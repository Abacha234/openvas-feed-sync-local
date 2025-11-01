# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58473");
  script_cve_id("CVE-2007-2926");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1341)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1341");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1341");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-1341 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides fixed packages for the oldstable distribution (sarge). For reference the original advisory text:

Amit Klein discovered that the BIND name server generates predictable DNS query IDs, which may lead to cache poisoning attacks.

For the oldstable distribution (sarge) this problem has been fixed in version 9.2.4-1sarge3. An update for mips, powerpc and hppa is not yet available, they will be released soon.

For the stable distribution (etch) this problem has been fixed in version 9.3.4-2etch1. An update for mips is not yet available, it will be released soon.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you upgrade your BIND packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);