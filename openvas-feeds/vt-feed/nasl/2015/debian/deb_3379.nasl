# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703379");
  script_cve_id("CVE-2015-6031");
  script_tag(name:"creation_date", value:"2015-10-24 22:00:00 +0000 (Sat, 24 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3379)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3379");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3379");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'miniupnpc' package(s) announced via the DSA-3379 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aleksandar Nikolic of Cisco Talos discovered a buffer overflow vulnerability in the XML parser functionality of miniupnpc, a UPnP IGD client lightweight library. A remote attacker can take advantage of this flaw to cause an application using the miniupnpc library to crash, or potentially to execute arbitrary code with the privileges of the user running the application.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.5-2+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 1.9.20140610-2+deb8u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your miniupnpc packages.");

  script_tag(name:"affected", value:"'miniupnpc' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);