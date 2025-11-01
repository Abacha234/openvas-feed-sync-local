# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702665");
  script_cve_id("CVE-2013-2944");
  script_tag(name:"creation_date", value:"2013-04-29 22:00:00 +0000 (Mon, 29 Apr 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2665)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2665");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2665");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'strongswan' package(s) announced via the DSA-2665 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kevin Wojtysiak discovered a vulnerability in strongSwan, an IPsec based VPN solution.

When using the OpenSSL plugin for ECDSA based authentication, an empty, zeroed or otherwise invalid signature is handled as a legitimate one. An attacker could use a forged signature to authenticate like a legitimate user and gain access to the VPN (and everything protected by this).

While the issue looks like CVE-2012-2388 (RSA signature based authentication bypass), it is unrelated.

For the stable distribution (squeeze), this problem has been fixed in version 4.4.1-5.3.

For the testing distribution (wheezy), this problem has been fixed in version 4.5.2-1.5+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 4.6.4-7.

We recommend that you upgrade your strongswan packages.");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);