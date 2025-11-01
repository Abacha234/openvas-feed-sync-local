# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856387");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-4467", "CVE-2024-7409");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 16:15:05 +0000 (Tue, 02 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-08-28 04:00:35 +0000 (Wed, 28 Aug 2024)");
  script_name("openSUSE: Security Advisory for qemu (SUSE-SU-2024:2983-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2983-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7RM3IRICZAZ5KYNMVDN2VEXGT4OYF7TQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the SUSE-SU-2024:2983-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

  * CVE-2024-4467: Fixed denial of service and file read/write via qemu-img info
      command (bsc#1227322)

  * CVE-2024-7409: Fixed denial of service via improper synchronization in QEMU
      NBD Server during socket closure (bsc#1229007)

  * nbd/server: Close stray clients at server-stop

  * nbd/server: Drop non-negotiating clients

  * nbd/server: Cap default max-connections to 100

  * nbd/server: Plumb in new args to nbd_client_add()

  * nbd: Minor style and typo fixes

  * Update qemu to version 8.2.6");

  script_tag(name:"affected", value:"'qemu' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
