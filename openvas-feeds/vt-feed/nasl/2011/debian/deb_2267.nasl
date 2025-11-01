# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69974");
  script_cve_id("CVE-2010-1447");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2267)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2267");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2267");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'perl' package(s) announced via the DSA-2267 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Perl's Safe module - a module to compile and execute code in restricted compartments - could be bypassed.

Please note that this update is known to break Petal, an XML-based templating engine (shipped with Debian 6.0/Squeeze in the package libpetal-perl, see bug #582805 for details). A fix is not yet available. If you use Petal, you might consider to put the previous Perl packages on hold.

For the oldstable distribution (lenny), this problem has been fixed in version 5.10.0-19lenny5.

For the stable distribution (squeeze), this problem has been fixed in version 5.10.1-17squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 5.12.3-1.

We recommend that you upgrade your perl packages.");

  script_tag(name:"affected", value:"'perl' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);