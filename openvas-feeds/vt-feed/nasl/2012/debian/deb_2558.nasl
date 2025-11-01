# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72475");
  script_cve_id("CVE-2012-4430");
  script_tag(name:"creation_date", value:"2012-10-13 06:34:56 +0000 (Sat, 13 Oct 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2558)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2558");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2558");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bacula' package(s) announced via the DSA-2558 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that bacula, a network backup service, does not properly enforce console ACLs. This could allow information about resources to be dumped by an otherwise-restricted client.

For the stable distribution (squeeze), this problem has been fixed in version 5.0.2-2.2+squeeze1.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 5.2.6+dfsg-4.

We recommend that you upgrade your bacula packages.");

  script_tag(name:"affected", value:"'bacula' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);