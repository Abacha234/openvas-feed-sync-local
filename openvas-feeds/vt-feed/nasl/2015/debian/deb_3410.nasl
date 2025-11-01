# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703410");
  script_cve_id("CVE-2015-4473", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4513", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");
  script_tag(name:"creation_date", value:"2015-11-30 23:00:00 +0000 (Mon, 30 Nov 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3410)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3410");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3410");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-3410 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Icedove, Debian's version of the Mozilla Thunderbird mail client: Multiple memory safety errors, integer overflows, buffer overflows and other implementation errors may lead to the execution of arbitrary code or denial of service.

For the oldstable distribution (wheezy), these problems have been fixed in version 38.4.0-1~deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 38.4.0-1~deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 38.4.0-1.

In addition enigmail has been updated to a release compatible with the new ESR38 series.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);