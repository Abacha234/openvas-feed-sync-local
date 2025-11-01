# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702797");
  script_cve_id("CVE-2013-5590", "CVE-2013-5595", "CVE-2013-5597", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5604");
  script_tag(name:"creation_date", value:"2013-11-12 23:00:00 +0000 (Tue, 12 Nov 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2797)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2797");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2797");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-2797 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Icedove, Debian's version of the Mozilla Thunderbird mail and news client. Multiple memory safety errors, and other implementation errors may lead to the execution of arbitrary code.

The Icedove version in the oldstable distribution (squeeze) is no longer supported with full security updates. However, it should be noted that almost all security issues in Icedove stem from the included browser engine. These security problems only affect Icedove if scripting and HTML mails are enabled. If there are security issues specific to Icedove (e.g. a hypothetical buffer overflow in the IMAP implementation) we'll make an effort to backport such fixes to oldstable.

For the stable distribution (wheezy), these problems have been fixed in version 17.0.10-1~deb7u1.

For the unstable distribution (sid), these problems have been fixed in version 17.0.10-1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);