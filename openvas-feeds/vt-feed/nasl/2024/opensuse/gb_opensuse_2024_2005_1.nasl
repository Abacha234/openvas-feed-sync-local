# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856218");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-0090", "CVE-2024-0091", "CVE-2024-0092");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-15 22:20:16 +0000 (Thu, 15 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-06-15 04:00:32 +0000 (Sat, 15 Jun 2024)");
  script_name("openSUSE: Security Advisory for kernel (SUSE-SU-2024:2005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2005-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SWKGDTDR5YESEMYE6VQYHALY475LFH2I");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the SUSE-SU-2024:2005-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware-nvidia-gspx-G06, nvidia-open-driver-G06-signed
  fixes the following issues:

  Security Update 550.90.07:

  * CVE-2024-0090: Fixed out of bounds write (bsc#1223356).

  * CVE-2024-0092: Fixed incorrect exception handling (bsc#1223356).

  * CVE-2024-0091: Fixed untrusted pointer dereference (bsc#1223356).

  ##");

  script_tag(name:"affected", value:"'kernel' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
