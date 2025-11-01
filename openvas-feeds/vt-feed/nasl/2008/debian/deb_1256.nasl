# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57833");
  script_cve_id("CVE-2007-0010");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1256)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1256");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1256");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gtk+2.0' package(s) announced via the DSA-1256 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the image loading code in the GTK+ graphical user interface library performs insufficient error handling when loading malformed images, which may lead to denial of service.

For the stable distribution (sarge) this problem has been fixed in version 2.6.4-3.2. This update lacks builds for the Motorola 680x0 architecture, which had build problems. Packages will be released once this problem has been resolved.

For the upcoming stable distribution (etch) this problem has been fixed in version 2.8.20-5.

For the unstable distribution (sid) this problem has been fixed in version 2.8.20-5.

We recommend that you upgrade your GTK packages.");

  script_tag(name:"affected", value:"'gtk+2.0' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);