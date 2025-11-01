# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703393");
  script_cve_id("CVE-2015-4513", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_tag(name:"creation_date", value:"2015-11-03 23:00:00 +0000 (Tue, 03 Nov 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3393)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3393");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3393");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-3393 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Iceweasel, Debian's version of the Mozilla Firefox web browser: Multiple memory safety errors, integer overflows, buffer overflows and other implementation errors may lead to the execution of arbitrary code, information disclosure or denial of service.

For the oldstable distribution (wheezy), these problems have been fixed in version 38.4.0esr-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 38.4.0esr-1~deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 38.4.0esr-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);