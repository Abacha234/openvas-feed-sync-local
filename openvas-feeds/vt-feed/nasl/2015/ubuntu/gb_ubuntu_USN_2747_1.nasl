# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842464");
  script_cve_id("CVE-2015-5950");
  script_tag(name:"creation_date", value:"2015-09-29 05:43:49 +0000 (Tue, 29 Sep 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2747-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2747-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2747-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jockey, nvidia-graphics-drivers-304, nvidia-graphics-drivers-304-updates, nvidia-graphics-drivers-340, nvidia-graphics-drivers-340-updates, nvidia-graphics-drivers-346, nvidia-graphics-drivers-346-updates' package(s) announced via the USN-2747-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dario Weisser discovered that the NVIDIA graphics drivers incorrectly
handled certain IOCTL writes. A local attacker could use this issue to
possibly gain root privileges.");

  script_tag(name:"affected", value:"'jockey, nvidia-graphics-drivers-304, nvidia-graphics-drivers-304-updates, nvidia-graphics-drivers-340, nvidia-graphics-drivers-340-updates, nvidia-graphics-drivers-346, nvidia-graphics-drivers-346-updates' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
