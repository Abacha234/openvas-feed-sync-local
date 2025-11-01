# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703600");
  script_cve_id("CVE-2016-2818", "CVE-2016-2819", "CVE-2016-2821", "CVE-2016-2822", "CVE-2016-2828", "CVE-2016-2831");
  script_tag(name:"creation_date", value:"2016-06-08 22:00:00 +0000 (Wed, 08 Jun 2016)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3600)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3600");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3600");
  script_xref(name:"URL", value:"https://glandium.org/blog/?p=3622");
  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/Mozilla_software_rebranded_by_Debian");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firefox-esr' package(s) announced via the DSA-3600 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Mozilla Firefox web browser: Multiple memory safety errors, buffer overflows and other implementation errors may lead to the execution of arbitrary code or spoofing.

Wait, Firefox? No more references to Iceweasel? That's right, Debian no longer applies a custom branding. Please see these links for further information: [link moved to references] [link moved to references]

Debian follows the extended support releases (ESR) of Firefox. Support for the 38.x series has ended, so starting with this update we're now following the 45.x releases and this update to the next ESR is also the point where we reapply the original branding.

Transition packages for the iceweasel packages are provided which automatically upgrade to the new version. Since new binary packages need to be installed, make sure to allow that in your upgrade procedure (e.g. by using apt-get dist-upgrade instead of apt-get upgrade).

For the stable distribution (jessie), these problems have been fixed in version 45.2.0esr-1~deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 45.2.0esr-1.

We recommend that you upgrade your firefox-esr packages.");

  script_tag(name:"affected", value:"'firefox-esr' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
