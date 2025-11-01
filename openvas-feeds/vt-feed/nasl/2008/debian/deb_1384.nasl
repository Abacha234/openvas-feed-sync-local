# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58643");
  script_cve_id("CVE-2007-1320", "CVE-2007-4993");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1384)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1384");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1384");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen-3.0' package(s) announced via the DSA-1384 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in the Xen hypervisor packages which may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-4993

By use of a specially crafted grub configuration file a domU user may be able to execute arbitrary code upon the dom0 when pygrub is being used.

CVE-2007-1320

Multiple heap-based buffer overflows in the Cirrus VGA extension, provided by QEMU, may allow local users to execute arbitrary code via bitblt heap overflow.

For the stable distribution (etch), these problems have been fixed in version 3.0.3-0-3.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your xen-utils package.");

  script_tag(name:"affected", value:"'xen-3.0' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);