# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53369");
  script_cve_id("CVE-2003-0213");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-295)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-295");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-295");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pptpd' package(s) announced via the DSA-295 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Timo Sirainen discovered a vulnerability in pptpd, a Point to Point Tunneling Server, which implements PPTP-over-IPSEC and is commonly used to create Virtual Private Networks (VPN). By specifying a small packet length an attacker is able to overflow a buffer and execute code under the user id that runs pptpd, probably root. An exploit for this problem is already circulating.

For the stable distribution (woody) this problem has been fixed in version 1.1.2-1.4.

For the old stable distribution (potato) this problem has been fixed in version 1.0.0-4.2.

For the unstable distribution (sid) this problem has been fixed in version 1.1.4-0.b3.2.

We recommend that you upgrade your pptpd package immediately.");

  script_tag(name:"affected", value:"'pptpd' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);