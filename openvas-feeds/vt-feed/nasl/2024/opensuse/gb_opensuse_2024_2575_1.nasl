# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856315");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-38417", "CVE-2023-47210");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-07-24 04:00:25 +0000 (Wed, 24 Jul 2024)");
  script_name("openSUSE: Security Advisory for kernel (SUSE-SU-2024:2575-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2575-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QO4ZKJFET2VLARC6HMSN3B2FGOSOOLE3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the SUSE-SU-2024:2575-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

  * CVE-2023-38417: Fixed improper input validation for some Intel(R)
      PROSet/Wireless WiFi software for linux before version 23.20 (bsc#1225600)

  * CVE-2023-47210: Fixed improper input validation for some Intel(R)
      PROSet/Wireless WiFi software before version 23.20 (bsc#1225601)

  * Update to version 20240712 (git commit ed874ed83cac):

  * amdgpu: update DMCUB to v0.0.225.0 for Various AMDGPU Asics

  * qcom: add gpu firmwares for x1e80100 chipset (bsc#1219458)

  * linux-firmware: add firmware for qat_402xx devices

  * amdgpu: update raven firmware

  * amdgpu: update SMU 13.0.10 firmware

  * amdgpu: update SDMA 6.0.3 firmware

  * amdgpu: update PSP 13.0.10 firmware

  * amdgpu: update GC 11.0.3 firmware

  * amdgpu: update vega20 firmware

  * amdgpu: update PSP 13.0.5 firmware

  * amdgpu: update PSP 13.0.8 firmware

  * amdgpu: update vega12 firmware

  * amdgpu: update vega10 firmware

  * amdgpu: update VCN 4.0.0 firmware

  * amdgpu: update SDMA 6.0.0 firmware

  * amdgpu: update PSP 13.0.0 firmware

  * amdgpu: update GC 11.0.0 firmware

  * amdgpu: update picasso firmware

  * amdgpu: update beige goby firmware

  * amdgpu: update vangogh firmware

  * amdgpu: update dimgrey cavefish firmware

  * amdgpu: update navy flounder firmware

  * amdgpu: update PSP 13.0.11 firmware

  * amdgpu: update GC 11.0.4 firmware

  * amdgpu: update green sardine firmware

  * amdgpu: update VCN 4.0.2 firmware

  * amdgpu: update SDMA 6.0.1 firmware

  * amdgpu: update PSP 13.0.4 firmware

  * amdgpu: update GC 11.0.1 firmware

  * amdgpu: update sienna cichlid firmware

  * amdgpu: update VPE 6.1.1 firmware

  * amdgpu: update VCN 4.0.6 firmware

  * amdgpu: update SDMA 6.1.1 firmware

  * amdgpu: update PSP 14.0.1 firmware

  * amdgpu: update GC 11.5.1 firmware

  * amdgpu: update VCN 4.0.5 firmware

  * amdgpu: update SDMA 6.1.0 firmware

  * amdgpu: update PSP 14.0.0 firmware

  * amdgpu: update GC 11.5.0 firmware

  * amdgpu: update navi14 firmware

  * amdgpu: update renoir firmware

  * amdgpu: update navi12 firmware

  * amdgpu: update PSP 13.0.6 firmware

  * amdgpu: update GC 9.4.3 firmware

  * amdgpu: update yellow carp firmware

  * amdgpu: update VCN 4.0.4 firmware

  * amdgpu: update SMU 13.0.7 firmware

  * amdgpu: update SDMA 6.0.2 firmware

  * amdgpu: update PSP 13.0.7 firmware

  * amdgpu: update GC 11.0.2 firmware

  * amdgpu: update navi10 firmware

  * amdgpu: update raven2 firmware

  * amdgpu: update aldebaran firmware

  * linux-f ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
