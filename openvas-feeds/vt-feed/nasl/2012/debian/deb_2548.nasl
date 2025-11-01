# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72177");
  script_cve_id("CVE-2012-3518", "CVE-2012-3519", "CVE-2012-4419", "CVE-2012-4922");
  script_tag(name:"creation_date", value:"2012-09-15 08:24:59 +0000 (Sat, 15 Sep 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2548)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2548");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2548");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tor' package(s) announced via the DSA-2548 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Tor, an online privacy tool.

CVE-2012-3518

Avoid an uninitialised memory read when reading a vote or consensus document that has an unrecognized flavour name. This could lead to a remote crash, resulting in denial of service.

CVE-2012-3519

Try to leak less information about what relays a client is choosing to a side-channel attacker.

CVE-2012-4419

By providing specially crafted date strings to a victim tor instance, an attacker can cause it to run into an assertion and shut down.

Additionally the update to stable includes the following fixes: when waiting for a client to renegotiate, don't allow it to add any bytes to the input buffer. This fixes a potential DoS issue [tor-5934, tor-6007].

For the stable distribution (squeeze), these problems have been fixed in version 0.2.2.39-1.

For the unstable distribution, these problems have been fixed in version 0.2.3.22-rc-1.

We recommend that you upgrade your tor packages.");

  script_tag(name:"affected", value:"'tor' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);