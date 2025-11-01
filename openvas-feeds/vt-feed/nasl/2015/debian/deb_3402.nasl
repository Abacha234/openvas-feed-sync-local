# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703402");
  script_cve_id("CVE-2015-8124", "CVE-2015-8125");
  script_tag(name:"creation_date", value:"2015-11-23 23:00:00 +0000 (Mon, 23 Nov 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3402)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3402");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3402");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'symfony' package(s) announced via the DSA-3402 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in symfony, a framework to create websites and web applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-8124

The RedTeam Pentesting GmbH team discovered a session fixation vulnerability within the Remember Me login feature, allowing an attacker to impersonate the victim towards the web application if the session id value was previously known to the attacker.

CVE-2015-8125

Several potential remote timing attack vulnerabilities were discovered in classes from the Symfony Security component and in the legacy CSRF implementation from the Symfony Form component.

For the stable distribution (jessie), these problems have been fixed in version 2.3.21+dfsg-4+deb8u2.

For the unstable distribution (sid), these problems have been fixed in version 2.7.7+dfsg-1.

We recommend that you upgrade your symfony packages.");

  script_tag(name:"affected", value:"'symfony' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);