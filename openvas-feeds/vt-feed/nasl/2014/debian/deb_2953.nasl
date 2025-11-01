# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702953");
  script_cve_id("CVE-2014-3864", "CVE-2014-3865");
  script_tag(name:"creation_date", value:"2014-06-07 22:00:00 +0000 (Sat, 07 Jun 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2953)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2953");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2953");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dpkg' package(s) announced via the DSA-2953 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in dpkg that allow file modification through path traversal when unpacking source packages with specially crafted patch files.

This update had been scheduled before the end of security support for the oldstable distribution (squeeze), hence an exception has been made and was released through the security archive. However, no further updates should be expected.

For the oldstable distribution (squeeze), these problems have been fixed in version 1.15.11.

For the stable distribution (wheezy), these problems have been fixed in version 1.16.15.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 1.17.10.

We recommend that you upgrade your dpkg packages.");

  script_tag(name:"affected", value:"'dpkg' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);