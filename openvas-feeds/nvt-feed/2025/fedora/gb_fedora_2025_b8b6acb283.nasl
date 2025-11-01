# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.988986979998283");
  script_cve_id("CVE-2025-8860");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-b8b6acb283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b8b6acb283");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b8b6acb283");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387590");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2391334");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the FEDORA-2025-b8b6acb283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix crash with spice GL (bz 2391334)

----

Update to 10.1.0 GA release


----

Automatic update for qemu-10.1.0-0.4.rc4.fc43.");

  script_tag(name:"affected", value:"'qemu' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa", rpm:"qemu-audio-alsa~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa-debuginfo", rpm:"qemu-audio-alsa-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-dbus", rpm:"qemu-audio-dbus~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-dbus-debuginfo", rpm:"qemu-audio-dbus-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-jack", rpm:"qemu-audio-jack~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-jack-debuginfo", rpm:"qemu-audio-jack-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss", rpm:"qemu-audio-oss~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-oss-debuginfo", rpm:"qemu-audio-oss-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa", rpm:"qemu-audio-pa~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa-debuginfo", rpm:"qemu-audio-pa-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pipewire", rpm:"qemu-audio-pipewire~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pipewire-debuginfo", rpm:"qemu-audio-pipewire-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-sdl", rpm:"qemu-audio-sdl~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-sdl-debuginfo", rpm:"qemu-audio-sdl-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-spice", rpm:"qemu-audio-spice~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-spice-debuginfo", rpm:"qemu-audio-spice-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-blkio", rpm:"qemu-block-blkio~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-blkio-debuginfo", rpm:"qemu-block-blkio-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg", rpm:"qemu-block-dmg~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg-debuginfo", rpm:"qemu-block-dmg-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-gluster", rpm:"qemu-block-gluster~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-gluster-debuginfo", rpm:"qemu-block-gluster-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi-debuginfo", rpm:"qemu-block-iscsi-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs", rpm:"qemu-block-nfs~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs-debuginfo", rpm:"qemu-block-nfs-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh-debuginfo", rpm:"qemu-block-ssh-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-char-baum", rpm:"qemu-char-baum~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-char-baum-debuginfo", rpm:"qemu-char-baum-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-char-spice", rpm:"qemu-char-spice~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-char-spice-debuginfo", rpm:"qemu-char-spice-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-common", rpm:"qemu-common~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-common-debuginfo", rpm:"qemu-common-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debuginfo", rpm:"qemu-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-qxl", rpm:"qemu-device-display-qxl~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-qxl-debuginfo", rpm:"qemu-device-display-qxl-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-vhost-user-gpu", rpm:"qemu-device-display-vhost-user-gpu~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-vhost-user-gpu-debuginfo", rpm:"qemu-device-display-vhost-user-gpu-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu", rpm:"qemu-device-display-virtio-gpu~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-ccw", rpm:"qemu-device-display-virtio-gpu-ccw~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-ccw-debuginfo", rpm:"qemu-device-display-virtio-gpu-ccw-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-debuginfo", rpm:"qemu-device-display-virtio-gpu-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-gl", rpm:"qemu-device-display-virtio-gpu-gl~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-gl-debuginfo", rpm:"qemu-device-display-virtio-gpu-gl-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci", rpm:"qemu-device-display-virtio-gpu-pci~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci-debuginfo", rpm:"qemu-device-display-virtio-gpu-pci-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci-gl", rpm:"qemu-device-display-virtio-gpu-pci-gl~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci-gl-debuginfo", rpm:"qemu-device-display-virtio-gpu-pci-gl-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci-rutabaga", rpm:"qemu-device-display-virtio-gpu-pci-rutabaga~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-pci-rutabaga-debuginfo", rpm:"qemu-device-display-virtio-gpu-pci-rutabaga-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-rutabaga", rpm:"qemu-device-display-virtio-gpu-rutabaga~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-gpu-rutabaga-debuginfo", rpm:"qemu-device-display-virtio-gpu-rutabaga-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga", rpm:"qemu-device-display-virtio-vga~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga-debuginfo", rpm:"qemu-device-display-virtio-vga-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga-gl", rpm:"qemu-device-display-virtio-vga-gl~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga-gl-debuginfo", rpm:"qemu-device-display-virtio-vga-gl-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga-rutabaga", rpm:"qemu-device-display-virtio-vga-rutabaga~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-display-virtio-vga-rutabaga-debuginfo", rpm:"qemu-device-display-virtio-vga-rutabaga-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-uefi-vars", rpm:"qemu-device-uefi-vars~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-uefi-vars-debuginfo", rpm:"qemu-device-uefi-vars-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-host", rpm:"qemu-device-usb-host~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-host-debuginfo", rpm:"qemu-device-usb-host-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-redirect", rpm:"qemu-device-usb-redirect~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-redirect-debuginfo", rpm:"qemu-device-usb-redirect-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-smartcard", rpm:"qemu-device-usb-smartcard~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-device-usb-smartcard-debuginfo", rpm:"qemu-device-usb-smartcard-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-docs", rpm:"qemu-docs~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img-debuginfo", rpm:"qemu-img-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-core", rpm:"qemu-kvm-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-pr-helper", rpm:"qemu-pr-helper~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-pr-helper-debuginfo", rpm:"qemu-pr-helper-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-aarch64", rpm:"qemu-system-aarch64~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-aarch64-core", rpm:"qemu-system-aarch64-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-aarch64-core-debuginfo", rpm:"qemu-system-aarch64-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-alpha", rpm:"qemu-system-alpha~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-alpha-core", rpm:"qemu-system-alpha-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-alpha-core-debuginfo", rpm:"qemu-system-alpha-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-arm", rpm:"qemu-system-arm~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-arm-core", rpm:"qemu-system-arm-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-arm-core-debuginfo", rpm:"qemu-system-arm-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-avr", rpm:"qemu-system-avr~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-avr-core", rpm:"qemu-system-avr-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-avr-core-debuginfo", rpm:"qemu-system-avr-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-hppa", rpm:"qemu-system-hppa~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-hppa-core", rpm:"qemu-system-hppa-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-hppa-core-debuginfo", rpm:"qemu-system-hppa-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-loongarch64", rpm:"qemu-system-loongarch64~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-loongarch64-core", rpm:"qemu-system-loongarch64-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-loongarch64-core-debuginfo", rpm:"qemu-system-loongarch64-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-m68k", rpm:"qemu-system-m68k~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-m68k-core", rpm:"qemu-system-m68k-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-m68k-core-debuginfo", rpm:"qemu-system-m68k-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-microblaze", rpm:"qemu-system-microblaze~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-microblaze-core", rpm:"qemu-system-microblaze-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-microblaze-core-debuginfo", rpm:"qemu-system-microblaze-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-mips", rpm:"qemu-system-mips~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-mips-core", rpm:"qemu-system-mips-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-mips-core-debuginfo", rpm:"qemu-system-mips-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-or1k", rpm:"qemu-system-or1k~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-or1k-core", rpm:"qemu-system-or1k-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-or1k-core-debuginfo", rpm:"qemu-system-or1k-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-ppc", rpm:"qemu-system-ppc~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-ppc-core", rpm:"qemu-system-ppc-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-ppc-core-debuginfo", rpm:"qemu-system-ppc-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-riscv", rpm:"qemu-system-riscv~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-riscv-core", rpm:"qemu-system-riscv-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-riscv-core-debuginfo", rpm:"qemu-system-riscv-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-rx", rpm:"qemu-system-rx~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-rx-core", rpm:"qemu-system-rx-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-rx-core-debuginfo", rpm:"qemu-system-rx-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-s390x", rpm:"qemu-system-s390x~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-s390x-core", rpm:"qemu-system-s390x-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-s390x-core-debuginfo", rpm:"qemu-system-s390x-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sh4", rpm:"qemu-system-sh4~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sh4-core", rpm:"qemu-system-sh4-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sh4-core-debuginfo", rpm:"qemu-system-sh4-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sparc", rpm:"qemu-system-sparc~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sparc-core", rpm:"qemu-system-sparc-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-sparc-core-debuginfo", rpm:"qemu-system-sparc-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-tricore", rpm:"qemu-system-tricore~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-tricore-core", rpm:"qemu-system-tricore-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-tricore-core-debuginfo", rpm:"qemu-system-tricore-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-x86", rpm:"qemu-system-x86~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-x86-core", rpm:"qemu-system-x86-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-x86-core-debuginfo", rpm:"qemu-system-x86-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-xtensa", rpm:"qemu-system-xtensa~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-xtensa-core", rpm:"qemu-system-xtensa-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-system-xtensa-core-debuginfo", rpm:"qemu-system-xtensa-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tests", rpm:"qemu-tests~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tests-debuginfo", rpm:"qemu-tests-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses", rpm:"qemu-ui-curses~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses-debuginfo", rpm:"qemu-ui-curses-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-dbus", rpm:"qemu-ui-dbus~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-dbus-debuginfo", rpm:"qemu-ui-dbus-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-egl-headless", rpm:"qemu-ui-egl-headless~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-egl-headless-debuginfo", rpm:"qemu-ui-egl-headless-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk", rpm:"qemu-ui-gtk~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk-debuginfo", rpm:"qemu-ui-gtk-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-opengl", rpm:"qemu-ui-opengl~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-opengl-debuginfo", rpm:"qemu-ui-opengl-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-sdl", rpm:"qemu-ui-sdl~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-sdl-debuginfo", rpm:"qemu-ui-sdl-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app", rpm:"qemu-ui-spice-app~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app-debuginfo", rpm:"qemu-ui-spice-app-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-core", rpm:"qemu-ui-spice-core~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-core-debuginfo", rpm:"qemu-ui-spice-core-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user", rpm:"qemu-user~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-binfmt", rpm:"qemu-user-binfmt~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-debuginfo", rpm:"qemu-user-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static", rpm:"qemu-user-static~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-aarch64", rpm:"qemu-user-static-aarch64~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-aarch64-debuginfo", rpm:"qemu-user-static-aarch64-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-alpha", rpm:"qemu-user-static-alpha~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-alpha-debuginfo", rpm:"qemu-user-static-alpha-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-arm", rpm:"qemu-user-static-arm~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-arm-debuginfo", rpm:"qemu-user-static-arm-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-hexagon", rpm:"qemu-user-static-hexagon~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-hexagon-debuginfo", rpm:"qemu-user-static-hexagon-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-hppa", rpm:"qemu-user-static-hppa~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-hppa-debuginfo", rpm:"qemu-user-static-hppa-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-loongarch64", rpm:"qemu-user-static-loongarch64~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-loongarch64-debuginfo", rpm:"qemu-user-static-loongarch64-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-m68k", rpm:"qemu-user-static-m68k~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-m68k-debuginfo", rpm:"qemu-user-static-m68k-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-microblaze", rpm:"qemu-user-static-microblaze~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-microblaze-debuginfo", rpm:"qemu-user-static-microblaze-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-mips", rpm:"qemu-user-static-mips~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-mips-debuginfo", rpm:"qemu-user-static-mips-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-or1k", rpm:"qemu-user-static-or1k~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-or1k-debuginfo", rpm:"qemu-user-static-or1k-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-ppc", rpm:"qemu-user-static-ppc~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-ppc-debuginfo", rpm:"qemu-user-static-ppc-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-riscv", rpm:"qemu-user-static-riscv~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-riscv-debuginfo", rpm:"qemu-user-static-riscv-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-s390x", rpm:"qemu-user-static-s390x~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-s390x-debuginfo", rpm:"qemu-user-static-s390x-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-sh4", rpm:"qemu-user-static-sh4~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-sh4-debuginfo", rpm:"qemu-user-static-sh4-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-sparc", rpm:"qemu-user-static-sparc~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-sparc-debuginfo", rpm:"qemu-user-static-sparc-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-x86", rpm:"qemu-user-static-x86~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-x86-debuginfo", rpm:"qemu-user-static-x86-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-xtensa", rpm:"qemu-user-static-xtensa~10.1.0~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-user-static-xtensa-debuginfo", rpm:"qemu-user-static-xtensa-debuginfo~10.1.0~6.fc43", rls:"FC43"))) {
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
