# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833182");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-45145");
  script_tag(name:"cvss_base", value:"2.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-30 12:50:12 +0000 (Mon, 30 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:56:54 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for redis7 (SUSE-SU-2024:0200-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0200-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7GYVX25FQ34AUPKUVSHHH3RN45J6JACW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis7'
  package(s) announced via the SUSE-SU-2024:0200-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for redis7 fixes the following issues:

  * CVE-2023-45145: Fixed a potential permission bypass due to a race condition
      during UNIX socket creation (bsc#1216376).

  The following non-security issues were fixed:

  * Redis services are no longer disabled after an upgrade (bsc#1212119).

  ##");

  script_tag(name:"affected", value:"'redis7' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
