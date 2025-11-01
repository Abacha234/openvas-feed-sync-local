# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833747");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-31022");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-13 19:19:02 +0000 (Mon, 13 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:54:23 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for kernel (SUSE-SU-2023:4427-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4427-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GJ5SZYOS3N3HRP4RUAVXJRLGPNQ7ADQV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the SUSE-SU-2023:4427-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware-nvidia-gspx-G06, nvidia-open-driver-G06-signed
  fixes the following issues:

  Security issue fixed:

  * CVE-2023-31022: Fixed NULL ptr deref in kernel module layer

  Changes in kernel-firmware-nvidia-gspx-G06:

  * update firmware to version 535.129.03

  * update firmware to version 535.113.01

  Changes in nvidia-open-driver-G06-signed:

  * Update to version 535.129.03

  * Add a devel package so other modules can be built against this one.
      [jira#PED-4964]

  * disabled build of nvidia-peermem module  it's no longer needed and never
      worked anyway (it was only a stub) [bsc#1211892]

  * preamble: added conflict to nvidia-gfxG05-kmp to prevent users from
      accidentally installing conflicting proprietary kernelspace drivers from CUDA
      repository

  * Update to version 535.113.01

  * kmp-post.sh/kmp-postun.sh:

  * add/remove nosimplefb=1 kernel option in order to fix Linux console also on
      sle15-sp6/Leap 15.6 kernel, which will come with simpledrm support

  ##");

  script_tag(name:"affected", value:"'kernel' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
