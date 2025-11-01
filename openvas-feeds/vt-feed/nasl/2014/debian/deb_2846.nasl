# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702846");
  script_cve_id("CVE-2013-6458", "CVE-2014-1447");
  script_tag(name:"creation_date", value:"2014-01-16 23:00:00 +0000 (Thu, 16 Jan 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2846)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2846");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2846");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libvirt' package(s) announced via the DSA-2846 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in Libvirt, a virtualisation abstraction library:

CVE-2013-6458

It was discovered that insecure job usage could lead to denial of service against libvirtd.

CVE-2014-1447

It was discovered that a race condition in keepalive handling could lead to denial of service against libvirtd.

For the stable distribution (wheezy), these problems have been fixed in version 0.9.12.3-1. This bugfix point release also addresses some additional bugfixes.

For the unstable distribution (sid), these problems have been fixed in version 1.2.1-1.

We recommend that you upgrade your libvirt packages.");

  script_tag(name:"affected", value:"'libvirt' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);