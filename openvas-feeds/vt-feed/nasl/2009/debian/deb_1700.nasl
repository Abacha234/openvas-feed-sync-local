# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63147");
  script_cve_id("CVE-2009-0050");
  script_tag(name:"creation_date", value:"2009-01-13 21:38:32 +0000 (Tue, 13 Jan 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1700)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1700");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1700");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lasso' package(s) announced via the DSA-1700 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Lasso, a library for Liberty Alliance and SAML protocols performs incorrect validation of the return value of OpenSSL's DSA_verify() function.

For the stable distribution (etch), this problem has been fixed in version 0.6.5-3+etch1.

For the upcoming stable distribution (lenny) and the unstable distribution (sid), this problem has been fixed in version 2.2.1-2.

We recommend that you upgrade your lasso package.");

  script_tag(name:"affected", value:"'lasso' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);