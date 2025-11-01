# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70057");
  script_cve_id("CVE-2011-1526");
  script_tag(name:"creation_date", value:"2011-08-07 15:37:07 +0000 (Sun, 07 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2283");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2283");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5-appl' package(s) announced via the DSA-2283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tim Zingelmann discovered that due an incorrect configure script the kerborised FTP server failed to set the effective GID correctly, resulting in privilege escalation.

The oldstable distribution (lenny) is not affected.

For the stable distribution (squeeze), this problem has been fixed in version 1.0.1-1.1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your krb5-appl packages.");

  script_tag(name:"affected", value:"'krb5-appl' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);