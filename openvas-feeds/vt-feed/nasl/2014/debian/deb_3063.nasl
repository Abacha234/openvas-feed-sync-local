# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703063");
  script_cve_id("CVE-2014-8483");
  script_tag(name:"creation_date", value:"2014-11-01 23:00:00 +0000 (Sat, 01 Nov 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3063)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3063");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3063");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'quassel' package(s) announced via the DSA-3063 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds read vulnerability was discovered in Quassel-core, one of the components of the distributed IRC client Quassel. An attacker can send a crafted message that crash to component causing a denial of services or disclosure of information from process memory.

For the stable distribution (wheezy), this problem has been fixed in version 0.8.0-1+deb7u3.

For the unstable distribution (sid), this problem has been fixed in version 0.10.0-2.1 (will be available soon).

We recommend that you upgrade your quassel packages.");

  script_tag(name:"affected", value:"'quassel' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);