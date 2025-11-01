# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891927");
  script_cve_id("CVE-2016-5126", "CVE-2016-5403", "CVE-2017-9375", "CVE-2019-12068", "CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378", "CVE-2019-15890");
  script_tag(name:"creation_date", value:"2019-09-21 02:00:23 +0000 (Sat, 21 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-1927)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1927");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1927");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'qemu' package(s) announced via the DLA-1927 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in QEMU, a fast processor emulator (notably used in KVM and Xen HVM virtualization).

CVE-2016-5126

Heap-based buffer overflow in the iscsi_aio_ioctl function in block/iscsi.c in QEMU allows local guest OS users to cause a denial of service (QEMU process crash) or possibly execute arbitrary code via a crafted iSCSI asynchronous I/O ioctl call.

CVE-2016-5403

The virtqueue_pop function in hw/virtio/virtio.c in QEMU allows local guest OS administrators to cause a denial of service (memory consumption and QEMU process crash) by submitting requests without waiting for completion.

CVE-2017-9375

QEMU, when built with USB xHCI controller emulator support, allows local guest OS privileged users to cause a denial of service (infinite recursive call) via vectors involving control transfer descriptors sequencing.

CVE-2019-12068

QEMU scsi disk backend: lsi: exit infinite loop while executing script

CVE-2019-12155

interface_release_resource in hw/display/qxl.c in QEMU has a NULL pointer dereference.

CVE-2019-13164

qemu-bridge-helper.c in QEMU does not ensure that a network interface name (obtained from bridge.conf or a --br=bridge option) is limited to the IFNAMSIZ size, which can lead to an ACL bypass.

CVE-2019-14378

ip_reass in ip_input.c in libslirp 4.0.0 has a heap-based buffer overflow via a large packet because it mishandles a case involving the first fragment.

CVE-2019-15890

libslirp 4.0.0, as used in QEMU, has a use-after-free in ip_reass in ip_input.c.

For Debian 8 Jessie, these problems have been fixed in version 1:2.1+dfsg-12+deb8u12.

We recommend that you upgrade your qemu packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);