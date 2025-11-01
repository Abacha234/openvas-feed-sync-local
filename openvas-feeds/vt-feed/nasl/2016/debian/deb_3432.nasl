# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703432");
  script_cve_id("CVE-2015-7201", "CVE-2015-7205", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214");
  script_tag(name:"creation_date", value:"2016-05-06 09:59:37 +0000 (Fri, 06 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3432)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3432");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3432");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-3432 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Icedove, Debian's version of the Mozilla Thunderbird mail client: Multiple memory safety errors, integer overflows, buffer overflows and other implementation errors may lead to the execution of arbitrary code or denial of service.

For the oldstable distribution (wheezy), these problems have been fixed in version 38.5.0-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 38.5.0-1~deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 38.5.0esr-1.

For the unstable distribution (sid), these problems have been fixed in version 38.5.0esr-1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);