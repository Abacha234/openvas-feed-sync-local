# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66514");
  script_cve_id("CVE-2009-3300");
  script_tag(name:"creation_date", value:"2009-12-14 22:06:43 +0000 (Mon, 14 Dec 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1947)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1947");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1947");
  script_xref(name:"URL", value:"http://shibboleth.internet2.edu/secadv/secadv_20091104.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'opensaml2, shibboleth-sp, shibboleth-sp2' package(s) announced via the DSA-1947 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matt Elder discovered that Shibboleth, a federated web single sign-on system is vulnerable to script injection through redirection URLs. More details can be found in the Shibboleth advisory at [link moved to references].

For the old stable distribution (etch), this problem has been fixed in version 1.3f.dfsg1-2+etch2 of shibboleth-sp.

For the stable distribution (lenny), this problem has been fixed in version 1.3.1.dfsg1-3+lenny2 of shibboleth-sp, version 2.0.dfsg1-4+lenny2 of shibboleth-sp2 and version 2.0-2+lenny2 of opensaml2.

For the unstable distribution (sid), this problem has been fixed in version 2.3+dfsg-1 of shibboleth-sp2, version 2.3-1 of opensaml2 and version 1.3.1-1 of xmltooling.

We recommend that you upgrade your Shibboleth packages.");

  script_tag(name:"affected", value:"'opensaml2, shibboleth-sp, shibboleth-sp2' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);