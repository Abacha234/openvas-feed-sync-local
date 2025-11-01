# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702591");
  script_cve_id("CVE-2012-2239", "CVE-2012-2243", "CVE-2012-2244", "CVE-2012-2246", "CVE-2012-2247", "CVE-2012-2253", "CVE-2012-6037");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2591)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2591");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2591");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mahara' package(s) announced via the DSA-2591 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Mahara, an electronic portfolio, weblog, and resume builder, which can result in cross-site scripting, clickjacking or arbitrary file execution.

For the stable distribution (squeeze), these problems have been fixed in version 1.2.6-2+squeeze6.

For the unstable distribution (sid), these problems have been fixed in version 1.5.1-3.1.

We recommend that you upgrade your mahara packages.");

  script_tag(name:"affected", value:"'mahara' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);