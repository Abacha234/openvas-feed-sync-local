# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886561");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-05-27 10:43:03 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for libopenmpt (FEDORA-2024-7562c26666)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7562c26666");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TMXIN5VZ2ZO67KDSJ563J7VMJF4F5MAO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libopenmpt'
  package(s) announced via the FEDORA-2024-7562c26666 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libopenmpt is a cross-platform C++ and C library to decode tracked music
files (modules) into a raw PCM audio stream.

libopenmpt is based on the player code of the OpenMPT project (Open
ModPlug Tracker). In order to avoid code base fragmentation, libopenmpt is
developed in the same source code repository as OpenMPT.");

  script_tag(name:"affected", value:"'libopenmpt' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
