# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70692");
  script_cve_id("CVE-2011-4073");
  script_tag(name:"creation_date", value:"2012-02-11 08:21:50 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2374)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2374");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2374");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openswan' package(s) announced via the DSA-2374 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The information security group at ETH Zurich discovered a denial of service vulnerability in the crypto helper handler of the IKE daemon pluto. More information can be found in the upstream advisory.

For the oldstable distribution (lenny), this problem has been fixed in version 1:2.4.12+dfsg-1.3+lenny4.

For the stable distribution (squeeze), this problem has been fixed in version 1:2.6.28+dfsg-5+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 1:2.6.37-1.

We recommend that you upgrade your openswan packages.");

  script_tag(name:"affected", value:"'openswan' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);