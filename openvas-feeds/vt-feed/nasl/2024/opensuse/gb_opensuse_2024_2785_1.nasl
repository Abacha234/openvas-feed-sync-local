# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856368");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-38417", "CVE-2023-47210");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-08-20 04:08:00 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for kernel (SUSE-SU-2024:2785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2785-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6BSAJHXT6MPEOADK3F62D4IUC7EB7WV4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the SUSE-SU-2024:2785-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

  Update to version 20240728:

  * amdgpu: update DMCUB to v0.0.227.0 for DCN35 and DCN351

  * Revert 'iwlwifi: update ty/So/Ma firmwares for core89-58 release'

  * linux-firmware: update firmware for MT7922 WiFi device

  * linux-firmware: update firmware for MT7921 WiFi device

  * linux-firmware: update firmware for mediatek bluetooth chip (MT7922)

  * linux-firmware: update firmware for mediatek bluetooth chip (MT7921)

  * iwlwifi: add gl FW for core89-58 release

  * iwlwifi: update ty/So/Ma firmwares for core89-58 release

  * iwlwifi: update cc/Qu/QuZ firmwares for core89-58 release

  * mediatek: Update mt8195 SOF firmware and sof-tplg

  * ASoC: tas2781: fix the license issue for tas781 firmware

  * rtl_bt: Update RTL8852B BT USB FW to 0x048F_4008

  * i915: Update Xe2LPD DMC to v2.21

  * qcom: move signed x1e80100 signed firmware to the SoC subdir

  * qcom: add video firmware file for vpu-3.0

  * intel: avs: Add topology file for I2S Analog Devices 4567

  * intel: avs: Add topology file for I2S Nuvoton 8825

  * intel: avs: Add topology file for I2S Maxim 98927

  * intel: avs: Add topology file for I2S Maxim 98373

  * intel: avs: Add topology file for I2S Maxim 98357a

  * intel: avs: Add topology file for I2S Dialog 7219

  * intel: avs: Add topology file for I2S Realtek 5663

  * intel: avs: Add topology file for I2S Realtek 5640

  * intel: avs: Add topology file for I2S Realtek 5514

  * intel: avs: Add topology file for I2S Realtek 298

  * intel: avs: Add topology file for I2S Realtek 286

  * intel: avs: Add topology file for I2S Realtek 274

  * intel: avs: Add topology file for Digital Microphone Array

  * intel: avs: Add topology file for HDMI codecs

  * intel: avs: Add topology file for HDAudio codecs

  * intel: avs: Update AudioDSP base firmware for APL-based platforms

  ## Special Instructions and Notes:

  * Please reboot the system after installing this update.

  ##");

  script_tag(name:"affected", value:"'kernel' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
