# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856845");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-7409", "CVE-2024-8354", "CVE-2024-8612");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-05 14:15:35 +0000 (Mon, 05 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-12-13 05:00:36 +0000 (Fri, 13 Dec 2024)");
  script_name("openSUSE: Security Advisory for qemu (SUSE-SU-2024:4304-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4304-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XNZWQYFFPMN3TTVNEBF7F3PDKBMPMG2H");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the SUSE-SU-2024:4304-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

  * CVE-2024-7409: Fixed denial of service via improper synchronization in QEMU
      NBD Server during socket closure (bsc#1229007)

  * CVE-2024-8354: Fixed assertion failure in usb_ep_get() in usb (bsc#1230834)

  * CVE-2024-8612: Fixed information leak in virtio devices (bsc#1230915)");

  script_tag(name:"affected", value:"'qemu' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
