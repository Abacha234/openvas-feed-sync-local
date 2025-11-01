# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703333");
  script_cve_id("CVE-2015-4473", "CVE-2015-4475", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4480", "CVE-2015-4484", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4492", "CVE-2015-4493");
  script_tag(name:"creation_date", value:"2015-08-11 22:00:00 +0000 (Tue, 11 Aug 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3333)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3333");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3333");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-3333 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Iceweasel, Debian's version of the Mozilla Firefox web browser: Multiple memory safety errors, integer overflows, buffer overflows, use-after-frees and other implementation errors may lead to the execution of arbitrary code, bypass of the same-origin policy or denial of service.

Debian follows the extended support releases (ESR) of Firefox. Support for the 31.x series has ended, so starting with this update we're now following the 38.x releases.

For the oldstable distribution (wheezy), these problems have been fixed in version 38.2.0esr-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 38.2.0esr-1~deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 38.2.0esr-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);