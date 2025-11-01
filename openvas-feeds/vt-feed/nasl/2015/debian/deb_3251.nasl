# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703251");
  script_cve_id("CVE-2015-3294");
  script_tag(name:"creation_date", value:"2015-05-04 22:00:00 +0000 (Mon, 04 May 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3251)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3251");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3251");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dnsmasq' package(s) announced via the DSA-3251 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nick Sampanis discovered that dnsmasq, a small caching DNS proxy and DHCP/TFTP server, did not properly check the return value of the setup_reply() function called during a TCP connection, which is used then as a size argument in a function which writes data on the client's connection. A remote attacker could exploit this issue via a specially crafted DNS request to cause dnsmasq to crash, or potentially to obtain sensitive information from process memory.

For the oldstable distribution (wheezy), this problem has been fixed in version 2.62-3+deb7u2.

For the stable distribution (jessie), this problem has been fixed in version 2.72-3+deb8u1.

For the testing distribution (stretch) and the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your dnsmasq packages.");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);