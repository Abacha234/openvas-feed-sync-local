# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53440");
  script_cve_id("CVE-2002-1279");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-194)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-194");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/dsa-194");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'masqmail' package(s) announced via the DSA-194 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A set of buffer overflows have been discovered in masqmail, a mail transport agent for hosts without permanent internet connection. In addition to this privileges were dropped only after reading a user supplied configuration file. Together this could be exploited to gain unauthorized root access to the machine on which masqmail is installed.

These problems have been fixed in version 0.1.16-2.1 for the current stable distribution (woody) and in version 0.2.15-1 for the unstable distribution (sid). The old stable distribution (potato) is not affected since it doesn't contain a masqmail package.

We recommend that you upgrade your masqmail package immediately.");

  script_tag(name:"affected", value:"'masqmail' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);