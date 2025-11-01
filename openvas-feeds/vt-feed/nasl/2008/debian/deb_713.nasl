# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53541");
  script_cve_id("CVE-2005-1108", "CVE-2005-1109");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-713)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-713");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-713");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'junkbuster' package(s) announced via the DSA-713 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several bugs have been found in junkbuster, a HTTP proxy and filter. The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CAN-2005-1108

James Ranson discovered that an attacker can modify the referrer setting with a carefully crafted URL by accidentally overwriting a global variable.

CAN-2005-1109

Tavis Ormandy from the Gentoo Security Team discovered several heap corruptions due to inconsistent use of an internal function that can crash the daemon or possibly lead to the execution of arbitrary code.

For the stable distribution (woody) these problems have been fixed in version 2.0.2-0.2woody1.

The unstable distribution (sid) doesn't contain the junkbuster package anymore.

We recommend that you upgrade your junkbuster package.");

  script_tag(name:"affected", value:"'junkbuster' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);