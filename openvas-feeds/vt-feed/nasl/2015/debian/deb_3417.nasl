# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703417");
  script_cve_id("CVE-2015-7940");
  script_tag(name:"creation_date", value:"2015-12-13 23:00:00 +0000 (Sun, 13 Dec 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3417)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3417");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3417");
  script_xref(name:"URL", value:"http://web-in-security.blogspot.ca/2015/09/practical-invalid-curve-attacks.html");
  script_xref(name:"URL", value:"http://euklid.org/pdf/ECC_Invalid_Curve.pdf");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bouncycastle' package(s) announced via the DSA-3417 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tibor Jager, Jorg Schwenk, and Juraj Somorovsky, from Horst Gortz Institute for IT Security, published a paper in ESORICS 2015 where they describe an invalid curve attack in Bouncy Castle Crypto, a Java library for cryptography. An attacker is able to recover private Elliptic Curve keys from different applications, for example, TLS servers.

More information: [link moved to references] Practical Invalid Curve Attacks on TLS-ECDH: [link moved to references]

For the oldstable distribution (wheezy), this problem has been fixed in version 1.44+dfsg-3.1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 1.49+dfsg-3+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 1.51-2.

We recommend that you upgrade your bouncycastle packages.");

  script_tag(name:"affected", value:"'bouncycastle' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);