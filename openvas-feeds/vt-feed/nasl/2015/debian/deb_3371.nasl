# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703371");
  script_cve_id("CVE-2015-5260", "CVE-2015-5261");
  script_tag(name:"creation_date", value:"2015-10-08 22:00:00 +0000 (Thu, 08 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-16 01:29:00 +0000 (Sat, 16 Sep 2017)");

  script_name("Debian: Security Advisory (DSA-3371)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3371");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3371");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'spice' package(s) announced via the DSA-3371 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Frediano Ziglio of Red Hat discovered several vulnerabilities in spice, a SPICE protocol client and server library. A malicious guest can exploit these flaws to cause a denial of service (QEMU process crash), execute arbitrary code on the host with the privileges of the hosting QEMU process or read and write arbitrary memory locations on the host.

For the oldstable distribution (wheezy), these problems have been fixed in version 0.11.0-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in version 0.12.5-1+deb8u2.

For the unstable distribution (sid), these problems have been fixed in version 0.12.5-1.3.

We recommend that you upgrade your spice packages.");

  script_tag(name:"affected", value:"'spice' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);