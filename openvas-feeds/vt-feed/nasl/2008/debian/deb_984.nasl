# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56356");
  script_cve_id("CVE-2005-2097", "CVE-2005-3191", "CVE-2005-3193", "CVE-2006-0301");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-984)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-984");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-984");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xpdf' package(s) announced via the DSA-984 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Derek Noonburg has fixed several potential vulnerabilities in xpdf, the Portable Document Format (PDF) suite.

The old stable distribution (woody) does not seem to be affected.

For the stable distribution (sarge) these problems have been fixed in version 3.00-13.6.

For the unstable distribution (sid) these problems have been fixed in version 3.01-7.

We recommend that you upgrade your xpdf packages.");

  script_tag(name:"affected", value:"'xpdf' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);