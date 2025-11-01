# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65003");
  script_cve_id("CVE-2009-3474", "CVE-2009-3475", "CVE-2009-3476");
  script_tag(name:"creation_date", value:"2009-10-06 00:49:40 +0000 (Tue, 06 Oct 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1896)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1896");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1896");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'opensaml, shibboleth-sp' package(s) announced via the DSA-1896 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the opensaml and shibboleth-sp packages, as used by Shibboleth 1.x:

Chris Ries discovered that decoding a crafted URL leads to a crash (and potentially, arbitrary code execution).

Ian Young discovered that embedded NUL characters in certificate names were not correctly handled, exposing configurations using PKIX trust validation to impersonation attacks.

Incorrect processing of SAML metadata ignored key usage constraints.

For the old stable distribution (etch), these problems have been fixed in version 1.3f.dfsg1-2+etch1 of the shibboleth-sp packages, and version 1.1a-2+etch1 of the opensaml packages.

For the stable distribution (lenny), these problems have been fixed in version 1.3.1.dfsg1-3+lenny1 of the shibboleth-sp packages, and version 1.1.1-2+lenny1 of the opensaml packages.

The unstable distribution (sid) does not contain Shibboleth 1.x packages.

This update requires restarting the affected services (mainly Apache) to become effective.

We recommend that you upgrade your Shibboleth 1.x packages.");

  script_tag(name:"affected", value:"'opensaml, shibboleth-sp' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);