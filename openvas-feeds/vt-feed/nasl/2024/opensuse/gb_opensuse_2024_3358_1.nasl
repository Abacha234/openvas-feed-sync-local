# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856501");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-22656", "CVE-2023-45221", "CVE-2023-47169", "CVE-2023-47282", "CVE-2023-48368", "CVE-2024-7055");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-09-23 04:00:28 +0000 (Mon, 23 Sep 2024)");
  script_name("openSUSE: Security Advisory for ffmpeg (SUSE-SU-2024:3358-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3358-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QSQTWHIT3RNQD76Y6EXZ2KRSSDTFBGUA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the SUSE-SU-2024:3358-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg-4 fixes the following issues:

  * Dropped support for libmfx to fix the following CVEs:

  * libmfx: improper input validation (CVE-2023-48368, bsc#1226897)

  * libmfx: improper buffer restrictions (CVE-2023-45221, bsc#1226898)

  * libmfx: out-of-bounds read (CVE-2023-22656, bsc#1226899)

  * libmfx: out-of-bounds write (CVE-2023-47282, bsc#1226900)

  * libmfx: improper buffer restrictions (CVE-2023-47169, bsc#1226901)

  * CVE-2024-7055: heap-based buffer overflow in pnmdec.c from the libavcodec
      library. (bsc#1229026)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
