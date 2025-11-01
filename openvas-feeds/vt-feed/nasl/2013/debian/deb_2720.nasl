# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702720");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0795", "CVE-2013-0801", "CVE-2013-1670", "CVE-2013-1674", "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681", "CVE-2013-1682", "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687", "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694", "CVE-2013-1697");
  script_tag(name:"creation_date", value:"2013-07-05 22:00:00 +0000 (Fri, 05 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2720)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2720");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2720");
  script_xref(name:"URL", value:"http://addons.mozilla.org");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2720 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Icedove, Debian's version of the Mozilla Thunderbird mail and news client. Multiple memory safety errors, use-after-free vulnerabilities, missing permission checks, incorrect memory handling and other implementation errors may lead to the execution of arbitrary code, privilege escalation, information disclosure or cross-site request forgery.

As already announced for Iceweasel: we're changing the approach for security updates for Icedove in stable-security: instead of backporting security fixes, we now provide releases based on the Extended Support Release branch. As such, this update introduces packages based on Thunderbird 17 and at some point in the future we will switch to the next ESR branch once ESR 17 has reached it's end of life.

Some Icedove extensions currently packaged in the Debian archive are not compatible with the new browser engine. Up-to-date and compatible versions can be retrieved from [link moved to references] as a short term solution.

An updated and compatible version of Enigmail is included with this update.

The Icedove version in the oldstable distribution (squeeze) is no longer supported with full security updates. However, it should be noted that almost all security issues in Icedove stem from the included browser engine. These security problems only affect Icedove if scripting and HTML mails are enabled. If there are security issues specific to Icedove (e.g. a hypothetical buffer overflow in the IMAP implementation) we'll make an effort to backport such fixes to oldstable.

For the stable distribution (wheezy), these problems have been fixed in version 17.0.7-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 17.0.7-1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);