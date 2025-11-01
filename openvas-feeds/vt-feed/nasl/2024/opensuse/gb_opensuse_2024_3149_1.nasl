# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856442");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-7008");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-23 13:15:07 +0000 (Sat, 23 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-09-07 04:00:27 +0000 (Sat, 07 Sep 2024)");
  script_name("openSUSE: Security Advisory for systemd (SUSE-SU-2024:3149-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3149-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/57ELWJKCZ5ANGYRI6X3AUCKNZLD64XV3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the SUSE-SU-2024:3149-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

  * CVE-2023-7008: Fixed man-in-the-middle due to unsigned name response in
      signed zone not refused when DNSSEC=yes (bsc#1218297)

  Other fixes: \- Unit: drop ProtectClock=yes from systemd-udevd.service
  (bsc#1226414) \- Don't mention any rpm macros inside comments, even if escaped
  (bsc#1228091) \- Skip redundant dependencies specified the LSB description that
  references the file name of the service itself for early boot scripts
  (bsc#1221479).

  ## Special Instructions and Notes:

  * Please reboot the system after installing this update.

  ##");

  script_tag(name:"affected", value:"'systemd' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
