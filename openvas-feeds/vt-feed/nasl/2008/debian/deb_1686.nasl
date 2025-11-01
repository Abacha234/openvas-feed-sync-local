# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62956");
  script_cve_id("CVE-2008-5297");
  script_tag(name:"creation_date", value:"2008-12-23 17:28:16 +0000 (Tue, 23 Dec 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1686)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1686");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1686");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'no-ip' package(s) announced via the DSA-1686 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow has been discovered in the HTTP parser of the No-IP.com Dynamic DNS update client, which may result in the execution of arbitrary code.

For the stable distribution (etch), this problem has been fixed in version 2.1.1-4+etch1.

For the upcoming stable distribution (lenny) and the unstable distribution (sid), this problem has been fixed in version 2.1.7-11.

We recommend that you upgrade your no-ip package.");

  script_tag(name:"affected", value:"'no-ip' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);