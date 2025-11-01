# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703293");
  script_tag(name:"creation_date", value:"2015-06-19 22:00:00 +0000 (Fri, 19 Jun 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3293)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3293");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3293");
  script_xref(name:"URL", value:"https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pyjwt' package(s) announced via the DSA-3293 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tim McLean discovered that pyjwt, a Python implementation of JSON Web Token, would try to verify an HMAC signature using an RSA or ECDSA public key as secret. This could allow remote attackers to trick applications expecting tokens signed with asymmetric keys, into accepting arbitrary tokens. For more information see: [link moved to references].

For the stable distribution (jessie), this problem has been fixed in version 0.2.1-1+deb8u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your pyjwt packages.");

  script_tag(name:"affected", value:"'pyjwt' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);