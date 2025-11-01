# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61779");
  script_cve_id("CVE-2008-4553");
  script_tag(name:"creation_date", value:"2008-11-01 00:55:10 +0000 (Sat, 01 Nov 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1657)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1657");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1657");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DSA-1657 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dmitry E. Oboukhov discovered that the qemu-make-debian-root script in qemu, fast processor emulator, creates temporary files insecurely, which may lead to a local denial of service through symlink attacks.

For the stable distribution (etch), this problem has been fixed in version 0.8.2-4etch2.

For the testing (lenny) and unstable distribution (sid), this problem has been fixed in version 0.9.1-6.

We recommend that you upgrade your qemu package.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);