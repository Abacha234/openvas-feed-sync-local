# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.974597370014");
  script_tag(name:"creation_date", value:"2025-12-01 04:25:36 +0000 (Mon, 01 Dec 2025)");
  script_version("2025-12-01T05:45:26+0000");
  script_tag(name:"last_modification", value:"2025-12-01 05:45:26 +0000 (Mon, 01 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-a45a370014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-a45a370014");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-a45a370014");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware' package(s) announced via the FEDORA-2025-a45a370014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 20251125:

* Revert 'amdgpu: update GC 11.0.1 firmware'
* QCA: Add Bluetooth firmware for WCN685x uart interface
* qcom: Add ADSP firmware for qcs6490-thundercomm-rubikpi3
* qcom: venus-5.4: update firmware binary for v5.4
* qcom: venus-5.4: remove unused firmware file
* iwlwifi: add Sc/Wh FW for core98-181 release
* amdgpu: DMCUB updates for various ASICs
* rtl_bt: Update RTL8852B BT USB FW to 0x42D3_4E04
* ASoC: tas2781: Add more symbol links on SPI devices
* amdgpu: update numerous firmware
* amdgpu: add vce1 firmware
* mediatek MT7922: update bluetooth firmware to 20251118163447
* update firmware for MT7922 WiFi device
* qcom: update ADSP, CDSP firmware for kaanapali platform, change the license
* qcom: add ADSP, CDSP firmware for sm8750 platform
* rtl_nic: add firmware rtl9151a-1
* qcom: Update aic100 firmware files
* mt76: add firmware for MT7990
* mt76: update firmware for MT7992/MT7996
* cirrus: cs35l57: Add firmware for a few Dell products
* cirrus: cs42l45: Add firmware for Cirrus Logic CS42L45 SDCA codec
* qcom: Add sdx35 Foxconn vendor firmware image file
* Update AMD cpu microcode");

  script_tag(name:"affected", value:"'linux-firmware' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"amd-gpu-firmware", rpm:"amd-gpu-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"amd-ucode-firmware", rpm:"amd-ucode-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"atheros-firmware", rpm:"atheros-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"brcmfmac-firmware", rpm:"brcmfmac-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cirrus-audio-firmware", rpm:"cirrus-audio-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dvb-firmware", rpm:"dvb-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-audio-firmware", rpm:"intel-audio-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-gpu-firmware", rpm:"intel-gpu-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"intel-vsc-firmware", rpm:"intel-vsc-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlegacy-firmware", rpm:"iwlegacy-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-dvm-firmware", rpm:"iwlwifi-dvm-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-mld-firmware", rpm:"iwlwifi-mld-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iwlwifi-mvm-firmware", rpm:"iwlwifi-mvm-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libertas-firmware", rpm:"libertas-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware", rpm:"linux-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linux-firmware-whence", rpm:"linux-firmware-whence~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liquidio-firmware", rpm:"liquidio-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediatek-firmware", rpm:"mediatek-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlxsw_spectrum-firmware", rpm:"mlxsw_spectrum-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mrvlprestera-firmware", rpm:"mrvlprestera-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mt7xxx-firmware", rpm:"mt7xxx-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netronome-firmware", rpm:"netronome-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nvidia-gpu-firmware", rpm:"nvidia-gpu-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nxpwireless-firmware", rpm:"nxpwireless-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-accel-firmware", rpm:"qcom-accel-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-firmware", rpm:"qcom-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qcom-wwan-firmware", rpm:"qcom-wwan-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qed-firmware", rpm:"qed-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"realtek-firmware", rpm:"realtek-firmware~20251125~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiwilink-firmware", rpm:"tiwilink-firmware~20251125~1.fc42", rls:"FC42"))) {
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
