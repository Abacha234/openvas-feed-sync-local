# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703414");
  script_cve_id("CVE-2015-3259", "CVE-2015-3340", "CVE-2015-5307", "CVE-2015-6654", "CVE-2015-7311", "CVE-2015-7812", "CVE-2015-7813", "CVE-2015-7814", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-7972", "CVE-2015-8104");
  script_tag(name:"creation_date", value:"2015-12-08 23:00:00 +0000 (Tue, 08 Dec 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3414)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3414");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3414");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-3414 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Xen virtualisation solution, which may result in denial of service or information disclosure.

For the oldstable distribution (wheezy), an update will be provided later.

For the stable distribution (jessie), these problems have been fixed in version 4.4.1-9+deb8u3.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);