# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66837");
  script_cve_id("CVE-2009-1629");
  script_tag(name:"creation_date", value:"2010-02-18 20:15:01 +0000 (Thu, 18 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1994)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1994");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1994");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ajaxterm' package(s) announced via the DSA-1994 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ajaxterm, a web-based terminal, generates weak and predictable session IDs, which might be used to hijack a session or cause a denial of service attack on a system that uses Ajaxterm.

For the oldstable distribution (etch), the problem has been fixed in version 0.9-2+etch1.

For the stable distribution (lenny), the problem has been fixed in version 0.10-2+lenny1.

For the unstable distribution (sid), the problem has been fixed in version 0.10-5.

We recommend that you upgrade your ajaxterm package.");

  script_tag(name:"affected", value:"'ajaxterm' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);