# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703282");
  script_cve_id("CVE-2015-4171");
  script_tag(name:"creation_date", value:"2015-06-07 22:00:00 +0000 (Sun, 07 Jun 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3282)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3282");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3282");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'strongswan' package(s) announced via the DSA-3282 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander E. Patrakov discovered an issue in strongSwan, an IKE/IPsec suite used to establish IPsec protected links.

When an IKEv2 client authenticates the server with certificates and the client authenticates itself to the server using pre-shared key or EAP, the constraints on the server certificate are only enforced by the client after all authentication steps are completed successfully. A rogue server which can authenticate using a valid certificate issued by any CA trusted by the client could trick the user into continuing the authentication, revealing the username and password digest (for EAP) or even the cleartext password (if EAP-GTC is accepted).

For the oldstable distribution (wheezy), this problem has been fixed in version 4.5.2-1.5+deb7u7.

For the stable distribution (jessie), this problem has been fixed in version 5.2.1-6+deb8u1.

For the testing distribution (stretch), this problem has been fixed in version 5.3.1-1.

For the unstable distribution (sid), this problem has been fixed in version 5.3.1-1.

We recommend that you upgrade your strongswan packages.");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);