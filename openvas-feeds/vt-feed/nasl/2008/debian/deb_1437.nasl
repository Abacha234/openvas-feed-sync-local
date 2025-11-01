# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60069");
  script_cve_id("CVE-2007-5849", "CVE-2007-6358");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1437)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1437");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1437");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cupsys' package(s) announced via the DSA-1437 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in the Common UNIX Printing System. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5849

Wei Wang discovered that an buffer overflow in the SNMP backend may lead to the execution of arbitrary code.

CVE-2007-6358

Elias Pipping discovered that insecure handling of a temporary file in the pdftops.pl script may lead to local denial of service. This vulnerability is not exploitable in the default configuration.

The old stable distribution (sarge) is not affected by CVE-2007-5849. The other issue doesn't warrant an update on it's own and has been postponed.

For the stable distribution (etch), these problems have been fixed in version 1.2.7-4etch2.

For the unstable distribution (sid), these problems have been fixed in version 1.3.5-1.

We recommend that you upgrade your cupsys packages.");

  script_tag(name:"affected", value:"'cupsys' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);