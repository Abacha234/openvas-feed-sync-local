# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840723");
  script_cve_id("CVE-2011-0084", "CVE-2011-2985", "CVE-2011-2987", "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2990", "CVE-2011-2991", "CVE-2011-2993");
  script_tag(name:"creation_date", value:"2011-08-19 13:17:22 +0000 (Fri, 19 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1192-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1192-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1192-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/825459");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozvoikko' package(s) announced via the USN-1192-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1192-1 fixed vulnerabilities in Firefox. This update provides an
updated Mozvoikko for use with Firefox 6.

Original advisory details:

 Aral Yaman discovered a vulnerability in the WebGL engine. An attacker
 could potentially use this to crash Firefox or execute arbitrary code with
 the privileges of the user invoking Firefox. (CVE-2011-2989)

 Vivekanand Bolajwar discovered a vulnerability in the JavaScript engine. An
 attacker could potentially use this to crash Firefox or execute arbitrary
 code with the privileges of the user invoking Firefox. (CVE-2011-2991)

 Bert Hubert and Theo Snelleman discovered a vulnerability in the Ogg
 reader. An attacker could potentially use this to crash Firefox or execute
 arbitrary code with the privileges of the user invoking Firefox.
 (CVE-2011-2991)

 Robert Kaiser, Jesse Ruderman, Gary Kwong, Christoph Diehl, Martijn
 Wargers, Travis Emmitt, Bob Clary, and Jonathan Watt discovered multiple
 memory vulnerabilities in the browser rendering engine. An attacker could
 use these to possibly execute arbitrary code with the privileges of the
 user invoking Firefox. (CVE-2011-2985)

 Rafael Gieschke discovered that unsigned JavaScript could call into a
 script inside a signed JAR. This could allow an attacker to execute
 arbitrary code with the identity and permissions of the signed JAR.
 (CVE-2011-2993)

 Michael Jordon discovered that an overly long shader program could cause a
 buffer overrun. An attacker could potentially use this to crash Firefox or
 execute arbitrary code with the privileges of the user invoking Firefox.
 (CVE-2011-2988)

 Michael Jordon discovered a heap overflow in the ANGLE library used in
 Firefox's WebGL implementation. An attacker could potentially use this to
 crash Firefox or execute arbitrary code with the privileges of the user
 invoking Firefox. (CVE-2011-2987)

 It was discovered that an SVG text manipulation routine contained a
 dangling pointer vulnerability. An attacker could potentially use this to
 crash Firefox or execute arbitrary code with the privileges of the user
 invoking Firefox. (CVE-2011-0084)

 Mike Cardwell discovered that Content Security Policy violation reports
 failed to strip out proxy authorization credentials from the list of
 request headers. This could allow a malicious website to capture proxy
 authorization credentials. Daniel Veditz discovered that redirecting to a
 website with Content Security Policy resulted in the incorrect resolution
 of hosts in the constructed policy. This could allow a malicious website to
 circumvent the Content Security Policy of another website. (CVE-2011-2990)");

  script_tag(name:"affected", value:"'mozvoikko' package(s) on Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
