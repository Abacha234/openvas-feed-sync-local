# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856830");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-36904", "CVE-2024-43861");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-03 13:45:12 +0000 (Tue, 03 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-12-11 05:00:22 +0000 (Wed, 11 Dec 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 22 for SLE 15 SP4) (SUSE-SU-2024:4276-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4276-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OANRUYCXIPE5N4KSSYCB3BUCEHKCKHCH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 22 for SLE 15 SP4)'
  package(s) announced via the SUSE-SU-2024:4276-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 5.14.21-150400_24_103 fixes several issues.

  The following security issues were fixed:

  * CVE-2024-36904: tcp: Use refcount_inc_not_zero() in tcp_twsk_unique()
      (bsc#1225733).

  * CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229553).");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 22 for SLE 15 SP4)' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
