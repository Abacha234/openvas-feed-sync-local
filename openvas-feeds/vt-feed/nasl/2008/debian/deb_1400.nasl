# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58733");
  script_cve_id("CVE-2007-5116");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1400)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1400");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1400");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'perl' package(s) announced via the DSA-1400 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Will Drewry and Tavis Ormandy of the Google Security Team have discovered a UTF-8 related heap overflow in Perl's regular expression compiler, probably allowing attackers to execute arbitrary code by compiling specially crafted regular expressions.

For the old stable distribution (sarge), this problem has been fixed in version 5.8.4-8sarge6.

For the stable distribution (etch), this problem has been fixed in version 5.8.8-7etch1.

For the unstable distribution (sid), this problem will be fixed soon.

Some architectures are missing from this DSA, these updates will be released once they are available.

We recommend that you upgrade your perl package.");

  script_tag(name:"affected", value:"'perl' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);