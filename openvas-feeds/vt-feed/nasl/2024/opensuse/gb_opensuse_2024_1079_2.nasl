# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856367");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-29025");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-08-20 04:08:00 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for netty, netty (SUSE-SU-2024:1079-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1079-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DNFWNFMMXV6G6KTUB6SCMHAH6ZOLBDPW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty, netty'
  package(s) announced via the SUSE-SU-2024:1079-2 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netty, netty-tcnative fixes the following issues:

  * CVE-2024-29025: Fixed out of memory due to large number of form fields
      (bsc#1222045).

  ##");

  script_tag(name:"affected", value:"'netty, netty' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
