# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842168");
  script_cve_id("CVE-2013-7439");
  script_tag(name:"creation_date", value:"2015-04-14 05:19:21 +0000 (Tue, 14 Apr 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2568-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2568-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2568-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libx11, libxrender' package(s) announced via the USN-2568-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Abhishek Arya discovered that libX11 incorrectly handled memory in the
MakeBigReq macro. A remote attacker could use this issue to cause
applications to crash, resulting in a denial of service, or possibly
execute arbitrary code.

In addition, following the macro fix in libx11, a number of other packages
have also been rebuilt as security updates including libxrender, libxext,
libxi, libxfixes, libxrandr, libsdl1.2, libxv, libxp, and
xserver-xorg-video-vmware.");

  script_tag(name:"affected", value:"'libx11, libxrender' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
