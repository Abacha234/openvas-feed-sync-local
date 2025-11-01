# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856499");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-22656", "CVE-2023-45221", "CVE-2023-47169", "CVE-2023-47282", "CVE-2023-48368");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-09-21 04:00:42 +0000 (Sat, 21 Sep 2024)");
  script_name("openSUSE: Security Advisory for libmfx (SUSE-SU-2024:3339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3339-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HBJ5B7FDCF4A3O3Z3RULI2X3HZUYP4PC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmfx'
  package(s) announced via the SUSE-SU-2024:3339-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libmfx fixes the following issues:

  * CVE-2023-48368: Fixed an improper input validation. (bsc#1226897)

  * CVE-2023-45221: Fixed an improper buffer restrictions. (bsc#1226898)

  * CVE-2023-22656: Fixed an out-of-bounds read. (bsc#1226899)

  * CVE-2023-47282: Fixed an out-of-bounds write. (bsc#1226900)

  * CVE-2023-47169: Fixed an improper buffer restrictions. (bsc#1226901)");

  script_tag(name:"affected", value:"'libmfx' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
