# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702789");
  script_cve_id("CVE-2013-6075");
  script_tag(name:"creation_date", value:"2013-10-31 23:00:00 +0000 (Thu, 31 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2789)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2789");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2789");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'strongswan' package(s) announced via the DSA-2789 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been found in the ASN.1 parser of strongSwan, an IKE daemon used to establish IPsec protected links.

By sending a crafted ID_DER_ASN1_DN ID payload to a vulnerable pluto or charon daemon, a malicious remote user can provoke a denial of service (daemon crash) or an authorization bypass (impersonating a different user, potentially acquiring VPN permissions she doesn't have).

For the oldstable distribution (squeeze), this problem has been fixed in version 4.4.1-5.4.

For the stable distribution (wheezy), this problem has been fixed in version 4.5.2-1.5+deb7u2.

For the testing distribution (jessie), this problem has been fixed in version 5.1.0-3.

For the unstable distribution (sid), this problem has been fixed in version 5.1.0-3.

We recommend that you upgrade your strongswan packages.");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);