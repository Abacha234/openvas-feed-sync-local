# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63679");
  script_cve_id("CVE-2009-0585");
  script_tag(name:"creation_date", value:"2009-03-31 17:20:21 +0000 (Tue, 31 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1748)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1748");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1748");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libsoup' package(s) announced via the DSA-1748 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libsoup, an HTTP library implementation in C, handles large strings insecurely via its Base64 encoding functions. This could possibly lead to the execution of arbitrary code.

For the oldstable distribution (etch), this problem has been fixed in version 2.2.98-2+etch1.

The stable distribution (lenny) is not affected by this issue.

The testing distribution (squeeze) and the unstable distribution (sid) are not affected by this issue.

We recommend that you upgrade your libsoup packages.");

  script_tag(name:"affected", value:"'libsoup' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);