# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60043");
  script_cve_id("CVE-2007-5395");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1432)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1432");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1432");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'link-grammar' package(s) announced via the DSA-1432 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alin Rad Pop discovered that link-grammar, Carnegie Mellon University's link grammar parser for English, performed insufficient validation within its tokenizer, which could allow a malicious input file to execute arbitrary code.

For the old stable distribution (sarge), this package is not present.

For the stable distribution (etch), this problem has been fixed in version 4.2.2-4etch1.

For the unstable distribution (sid), this problem has been fixed in version 4.2.5-1.

We recommend that you upgrade your link-grammar package.");

  script_tag(name:"affected", value:"'link-grammar' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);