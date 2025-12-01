# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.01011027552461");
  script_tag(name:"creation_date", value:"2025-11-28 08:39:12 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-0ef7552461)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-0ef7552461");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-0ef7552461");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware' package(s) announced via the FEDORA-2025-0ef7552461 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Upstream linux-firmware 20251111 release:

* rtl_bt: Update RTL8922A BT USB firmware to 0x41C0_C905
* add firmware for mt7987 internal 2.5G ethernet phy
* rtw88: 8822b: Update firmware to v30.20.0
* rtl_nic: add firmware rtl8125k-1
* ASoC: tas2781: Update dsp firmware for HP and ASUS projects
* amdgpu: DMCUB updates for various ASICs
* qcom: add SOCCP firmware for kaanapali platform
* xe: Update GUC to v70.53.0 for BMG, LNL, PTL
* i915: Update GUC to v70.53.0 for DG2, MTL
* rtw89: 8851b: update fw to v0.29.41.5
* rtw89: 8852b: update fw to v0.29.128.0 with format suffix -2
* rtw89: 8852b: update fw to v0.29.29.14
* rtw89: 8852bt: update fw to v0.29.127.0 with format suffix -1
* Update firmware file for Intel BlazarI/BlazarU core
* Create audio folder in ti folder, and move all the audio firmwares into it
* amdgpu: DMCUB updates for various ASICs
* Update AMD cpu microcode
* mediatek MT7925: update bluetooth firmware to 20251015213201
* rtl_bt: Add firmware and config files for RTL8761CUV
* Update AMD cpu microcode
* qcom: add ADSP firmware for kaanapali platform
* amdgpu: DMCUB updates for various ASICs
* mediatek MT7920: update bluetooth firmware to 20251020151255
* update firmware for MT7920/MT7922/MT7925 WiFi device
* amd-ucode: Fix minimum revisions in README
* cirrus: cs35l41: Rename various Asus Laptop firmware files to not have Speaker ID
* mediatek MT7922: update bluetooth firmware to 20251020143443");

  script_tag(name:"affected", value:"'linux-firmware' package(s) on Fedora 43.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"amd-gpu-firmware", rpm:"amd-gpu-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"amd-ucode-firmware", rpm:"amd-ucode-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atheros-firmware", rpm:"atheros-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brcmfmac-firmware", rpm:"brcmfmac-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cirrus-audio-firmware", rpm:"cirrus-audio-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvb-firmware", rpm:"dvb-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-audio-firmware", rpm:"intel-audio-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-gpu-firmware", rpm:"intel-gpu-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-vsc-firmware", rpm:"intel-vsc-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlegacy-firmware", rpm:"iwlegacy-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-dvm-firmware", rpm:"iwlwifi-dvm-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-mld-firmware", rpm:"iwlwifi-mld-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-mvm-firmware", rpm:"iwlwifi-mvm-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libertas-firmware", rpm:"libertas-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware-whence", rpm:"linux-firmware-whence~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liquidio-firmware", rpm:"liquidio-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediatek-firmware", rpm:"mediatek-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlxsw_spectrum-firmware", rpm:"mlxsw_spectrum-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mrvlprestera-firmware", rpm:"mrvlprestera-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mt7xxx-firmware", rpm:"mt7xxx-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netronome-firmware", rpm:"netronome-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-gpu-firmware", rpm:"nvidia-gpu-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nxpwireless-firmware", rpm:"nxpwireless-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-accel-firmware", rpm:"qcom-accel-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-firmware", rpm:"qcom-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-wwan-firmware", rpm:"qcom-wwan-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qed-firmware", rpm:"qed-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"realtek-firmware", rpm:"realtek-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiwilink-firmware", rpm:"tiwilink-firmware~20251111~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
