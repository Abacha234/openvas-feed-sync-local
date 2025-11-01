# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63333");
  script_cve_id("CVE-2008-5262");
  script_tag(name:"creation_date", value:"2009-02-10 14:52:40 +0000 (Tue, 10 Feb 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1717)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1717");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1717");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'devil' package(s) announced via the DSA-1717 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Cornelius discovered a buffer overflow in devil, a cross-platform image loading and manipulation toolkit, which could be triggered via a crafted Radiance RGBE file. This could potentially lead to the execution of arbitrary code.

For the stable distribution (etch), this problem has been fixed in version 1.6.7-5+etch1.

For the testing distribution (lenny), this problem has been fixed in version 1.6.8-rc2-3+lenny1.

For the unstable distribution (sid), this problem has been fixed in version 1.7.5-4.

We recommend that you upgrade your devil package.");

  script_tag(name:"affected", value:"'devil' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);