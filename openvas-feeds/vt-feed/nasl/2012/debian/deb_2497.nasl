# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71476");
  script_cve_id("CVE-2012-1820");
  script_tag(name:"creation_date", value:"2012-08-10 07:06:44 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2497)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2497");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2497");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'quagga' package(s) announced via the DSA-2497 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Quagga, a routing daemon, contains a vulnerability in processing the ORF capability in BGP OPEN messages. A malformed OPEN message from a previously configured BGP peer could cause bgpd to crash, causing a denial of service.

For the stable distribution (squeeze), this problem has been fixed in version 0.99.20.1-0+squeeze3.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 0.99.21-3.

We recommend that you upgrade your quagga packages.");

  script_tag(name:"affected", value:"'quagga' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);