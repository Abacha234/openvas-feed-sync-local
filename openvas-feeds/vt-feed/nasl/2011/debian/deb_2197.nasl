# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69333");
  script_cve_id("CVE-2010-1674", "CVE-2010-1675");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2197)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2197");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2197");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'quagga' package(s) announced via the DSA-2197 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that the Quagga routing daemon contains two denial-of-service vulnerabilities in its BGP implementation:

CVE-2010-1674

A crafted Extended Communities attribute triggers a NULL pointer dereference which causes the BGP daemon to crash. The crafted attributes are not propagated by the Internet core, so only explicitly configured direct peers are able to exploit this vulnerability in typical configurations.

CVE-2010-1675

The BGP daemon resets BGP sessions when it encounters malformed AS_PATHLIMIT attributes, introducing a distributed BGP session reset vulnerability which disrupts packet forwarding. Such malformed attributes are propagated by the Internet core, and exploitation of this vulnerability is not restricted to directly configured BGP peers.

This security update removes AS_PATHLIMIT processing from the BGP implementation, preserving the configuration statements for backwards compatibility. (Standardization of this BGP extension was abandoned long ago.)

For the oldstable distribution (lenny), these problems have been fixed in version 0.99.10-1lenny5.

For the stable distribution (squeeze), these problems have been fixed in version 0.99.17-2+squeeze2.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your quagga packages.");

  script_tag(name:"affected", value:"'quagga' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);