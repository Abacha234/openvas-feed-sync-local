# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702699");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0773", "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783", "CVE-2013-0787", "CVE-2013-0788", "CVE-2013-0793", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0800", "CVE-2013-0801", "CVE-2013-1670", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681");
  script_tag(name:"creation_date", value:"2013-06-01 22:00:00 +0000 (Sat, 01 Jun 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2699)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2699");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2699");
  script_xref(name:"URL", value:"http://addons.mozilla.org");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-2699 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Iceweasel, Debian's version of the Mozilla Firefox web browser: Multiple memory safety errors, missing input sanitising vulnerabilities, use-after-free vulnerabilities, buffer overflows and other programming errors may lead to the execution of arbitrary code, privilege escalation, information leaks or cross-site-scripting.

We're changing the approach for security updates for Iceweasel, Icedove and Iceape in stable-security: Instead of backporting security fixes, we now provide releases based on the Extended Support Release branch. As such, this update introduces packages based on Firefox 17 and at some point in the future we will switch to the next ESR branch once ESR 17 has reached it's end of life.

Some Xul extensions currently packaged in the Debian archive are not compatible with the new browser engine. Up-to-date and compatible versions can be retrieved from [link moved to references] as a short term solution. A solution to keep packaged extensions compatible with the Mozilla releases is still being sorted out.

We don't have the resources to backport security fixes to the Iceweasel release in oldstable-security any longer. If you're up to the task and want to help, please get in touch with team@security.debian.org. Otherwise, we'll announce the end of security support for Iceweasel, Icedove and Iceape in Squeeze in the next update round.

For the stable distribution (wheezy), these problems have been fixed in version 17.0.6esr-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 17.0.6esr-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);