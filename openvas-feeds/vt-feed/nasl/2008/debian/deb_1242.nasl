# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57750");
  script_cve_id("CVE-2006-5063", "CVE-2006-5790", "CVE-2006-5791", "CVE-2006-6318");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1242)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1242");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1242");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'elog' package(s) announced via the DSA-1242 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in elog, a web-based electronic logbook, which may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-5063

Tilman Koschnick discovered that log entry editing in HTML is vulnerable to cross-site scripting. This update disables the vulnerable code.

CVE-2006-5790

Ulf Harnhammar of the Debian Security Audit Project discovered several format string vulnerabilities in elog, which may lead to execution of arbitrary code.

CVE-2006-5791

Ulf Harnhammar of the Debian Security Audit Project discovered cross-site scripting vulnerabilities in the creation of new logbook entries.

CVE-2006-6318

Jayesh KS and Arun Kethipelly of OS2A discovered that elog performs insufficient error handling in config file parsing, which may lead to denial of service through a NULL pointer dereference.

For the stable distribution (sarge) these problems have been fixed in version 2.5.7+r1558-4+sarge3.

The upcoming stable distribution (etch) will no longer include elog.

For the unstable distribution (sid) these problems have been fixed in version 2.6.2+r1754-1.

We recommend that you upgrade your elog package.");

  script_tag(name:"affected", value:"'elog' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);