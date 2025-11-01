# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885165");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:39 +0000 (Sun, 05 Nov 2023)");
  script_name("Fedora: Security Advisory for attract-mode (FEDORA-2023-c8c68d30a1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c8c68d30a1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZHOKZULCYIF25CRLE7P6Z6RO7QJVMNCT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'attract-mode'
  package(s) announced via the FEDORA-2023-c8c68d30a1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Attract-Mode is a graphical frontend for command line emulators such as MAME,
MESS, and Nestopia. It hides the underlying operating system and is intended
to be controlled with a joystick, gamepad or spin dial, making it ideal for
use in arcade cabinet setups.");

  script_tag(name:"affected", value:"'attract-mode' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
