# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2025.6053");
  script_cve_id("CVE-2025-21861", "CVE-2025-39929", "CVE-2025-39931", "CVE-2025-39934", "CVE-2025-39937", "CVE-2025-39938", "CVE-2025-39942", "CVE-2025-39943", "CVE-2025-39944", "CVE-2025-39945", "CVE-2025-39946", "CVE-2025-39949", "CVE-2025-39951", "CVE-2025-39953", "CVE-2025-39955", "CVE-2025-39957", "CVE-2025-39964", "CVE-2025-39967", "CVE-2025-39968", "CVE-2025-39969", "CVE-2025-39970", "CVE-2025-39971", "CVE-2025-39972", "CVE-2025-39973", "CVE-2025-39977", "CVE-2025-39978", "CVE-2025-39980", "CVE-2025-39982", "CVE-2025-39985", "CVE-2025-39986", "CVE-2025-39987", "CVE-2025-39988", "CVE-2025-39993", "CVE-2025-39994", "CVE-2025-39995", "CVE-2025-39996", "CVE-2025-39998", "CVE-2025-40001", "CVE-2025-40006", "CVE-2025-40008", "CVE-2025-40010", "CVE-2025-40011", "CVE-2025-40013", "CVE-2025-40018", "CVE-2025-40019", "CVE-2025-40020", "CVE-2025-40021", "CVE-2025-40022", "CVE-2025-40026", "CVE-2025-40027", "CVE-2025-40029", "CVE-2025-40030", "CVE-2025-40032", "CVE-2025-40035", "CVE-2025-40036", "CVE-2025-40040", "CVE-2025-40042", "CVE-2025-40043", "CVE-2025-40044", "CVE-2025-40048", "CVE-2025-40049", "CVE-2025-40051", "CVE-2025-40053", "CVE-2025-40055", "CVE-2025-40056", "CVE-2025-40060", "CVE-2025-40062", "CVE-2025-40068", "CVE-2025-40070", "CVE-2025-40078", "CVE-2025-40080", "CVE-2025-40081", "CVE-2025-40084", "CVE-2025-40085", "CVE-2025-40087", "CVE-2025-40088", "CVE-2025-40092", "CVE-2025-40093", "CVE-2025-40094", "CVE-2025-40095", "CVE-2025-40096", "CVE-2025-40099", "CVE-2025-40100", "CVE-2025-40103", "CVE-2025-40104", "CVE-2025-40105", "CVE-2025-40106", "CVE-2025-40107", "CVE-2025-40109");
  script_tag(name:"creation_date", value:"2025-11-12 04:07:20 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-12T05:40:18+0000");
  script_tag(name:"last_modification", value:"2025-11-12 05:40:18 +0000 (Wed, 12 Nov 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-13 21:14:01 +0000 (Thu, 13 Mar 2025)");

  script_name("Debian: Security Advisory (DSA-6053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-6053-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2025/DSA-6053-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-6053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 12.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"affs-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"bpftool", ver:"7.1.0+6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-extra-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dasd-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"f2fs-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fancontrol-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hypervisor-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-12-arm", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-12-s390", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-12-x86", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-6.1", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-6.1", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4kc-malta", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5kc-malta", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-4kc-malta", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-5kc-malta", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-686", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-686-pae", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-amd64", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-arm64", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-armmp", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-armmp-lpae", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-cloud-amd64", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-cloud-arm64", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-common", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-common-rt", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-loongson-3", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-marvell", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-mips32r2el", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-mips64r2el", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-octeon", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-powerpc64le", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-rpi", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-rt-686-pae", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-rt-amd64", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-rt-arm64", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-rt-armmp", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-41-s390x", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-armmp-lpae", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-loongson-3", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-marvell", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-mips32r2el", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-mips64r2el", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-octeon", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-powerpc64le", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rpi", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-rt-armmp", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-s390x", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4kc-malta-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5kc-malta-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-4kc-malta", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-4kc-malta-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-5kc-malta", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-5kc-malta-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-686-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-686-pae-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-686-pae-unsigned", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-686-unsigned", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-amd64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-amd64-unsigned", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-arm64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-arm64-unsigned", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-armmp", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-armmp-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-armmp-lpae", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-armmp-lpae-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-cloud-amd64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-cloud-amd64-unsigned", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-cloud-arm64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-cloud-arm64-unsigned", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-loongson-3", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-loongson-3-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-marvell", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-marvell-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-mips32r2el", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-mips32r2el-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-mips64r2el", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-mips64r2el-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-octeon", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-octeon-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-powerpc64le", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-powerpc64le-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-rpi", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-rpi-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-rt-686-pae-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-rt-686-pae-unsigned", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-rt-amd64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-rt-amd64-unsigned", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-rt-arm64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-rt-arm64-unsigned", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-rt-armmp", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-rt-armmp-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-s390x", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-41-s390x-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-686-pae-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-amd64-signed-template", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-arm64-signed-template", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-armmp-lpae-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-amd64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-cloud-arm64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-i386-signed-template", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-loongson-3-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-marvell-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-mips32r2el", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-mips32r2el-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-mips64r2el", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-mips64r2el-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-octeon-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-powerpc64le-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rpi-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-686-pae-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-amd64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-arm64-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-rt-armmp-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-s390x-dbg", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-6.1", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-6.1", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-6.1.0-41", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-core-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nfs-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rtla", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-nic-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-41-armmp-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-41-marvell-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"2.0+6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-41-4kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-41-5kc-malta-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-41-loongson-3-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-41-mips32r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-41-mips64r2el-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-41-octeon-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-41-powerpc64le-di", ver:"6.1.158-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-6.1.0-41-s390x-di", ver:"6.1.158-1", rls:"DEB12"))) {
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
