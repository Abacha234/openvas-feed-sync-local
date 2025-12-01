# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2025.4379");
  script_cve_id("CVE-2025-21861", "CVE-2025-39929", "CVE-2025-39931", "CVE-2025-39934", "CVE-2025-39937", "CVE-2025-39938", "CVE-2025-39942", "CVE-2025-39943", "CVE-2025-39944", "CVE-2025-39945", "CVE-2025-39946", "CVE-2025-39949", "CVE-2025-39951", "CVE-2025-39953", "CVE-2025-39955", "CVE-2025-39957", "CVE-2025-39964", "CVE-2025-39967", "CVE-2025-39968", "CVE-2025-39969", "CVE-2025-39970", "CVE-2025-39971", "CVE-2025-39972", "CVE-2025-39973", "CVE-2025-39977", "CVE-2025-39978", "CVE-2025-39980", "CVE-2025-39982", "CVE-2025-39985", "CVE-2025-39986", "CVE-2025-39987", "CVE-2025-39988", "CVE-2025-39993", "CVE-2025-39994", "CVE-2025-39995", "CVE-2025-39996", "CVE-2025-39998", "CVE-2025-40001", "CVE-2025-40006", "CVE-2025-40008", "CVE-2025-40010", "CVE-2025-40011", "CVE-2025-40013", "CVE-2025-40018", "CVE-2025-40019", "CVE-2025-40020", "CVE-2025-40021", "CVE-2025-40022", "CVE-2025-40026", "CVE-2025-40027", "CVE-2025-40029", "CVE-2025-40030", "CVE-2025-40032", "CVE-2025-40035", "CVE-2025-40036", "CVE-2025-40040", "CVE-2025-40042", "CVE-2025-40043", "CVE-2025-40044", "CVE-2025-40048", "CVE-2025-40049", "CVE-2025-40051", "CVE-2025-40053", "CVE-2025-40055", "CVE-2025-40056", "CVE-2025-40060", "CVE-2025-40062", "CVE-2025-40068", "CVE-2025-40070", "CVE-2025-40078", "CVE-2025-40080", "CVE-2025-40081", "CVE-2025-40084", "CVE-2025-40085", "CVE-2025-40087", "CVE-2025-40088", "CVE-2025-40092", "CVE-2025-40093", "CVE-2025-40094", "CVE-2025-40095", "CVE-2025-40096", "CVE-2025-40099", "CVE-2025-40100", "CVE-2025-40103", "CVE-2025-40104", "CVE-2025-40105", "CVE-2025-40106", "CVE-2025-40107", "CVE-2025-40109", "CVE-2025-40111", "CVE-2025-40112", "CVE-2025-40115", "CVE-2025-40116", "CVE-2025-40118", "CVE-2025-40120", "CVE-2025-40121", "CVE-2025-40123", "CVE-2025-40124", "CVE-2025-40125", "CVE-2025-40126", "CVE-2025-40127", "CVE-2025-40134", "CVE-2025-40140", "CVE-2025-40141", "CVE-2025-40153", "CVE-2025-40154", "CVE-2025-40156", "CVE-2025-40167", "CVE-2025-40171", "CVE-2025-40173", "CVE-2025-40176", "CVE-2025-40178", "CVE-2025-40179", "CVE-2025-40183", "CVE-2025-40186", "CVE-2025-40187", "CVE-2025-40188", "CVE-2025-40190", "CVE-2025-40193", "CVE-2025-40194", "CVE-2025-40197", "CVE-2025-40198", "CVE-2025-40200", "CVE-2025-40201", "CVE-2025-40202", "CVE-2025-40204", "CVE-2025-40205", "CVE-2025-40207");
  script_tag(name:"creation_date", value:"2025-11-26 04:09:15 +0000 (Wed, 26 Nov 2025)");
  script_version("2025-11-26T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-26 05:40:08 +0000 (Wed, 26 Nov 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-13 21:14:01 +0000 (Thu, 13 Mar 2025)");

  script_name("Debian: Security Advisory (DLA-4379-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4379-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2025/DLA-4379-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-6.1' package(s) announced via the DLA-4379-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'linux-6.1' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-6.1", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-6.1", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-armmp", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-armmp-lpae", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1-rt-armmp", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-686", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-686-pae", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-amd64", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-arm64", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-armmp", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-armmp-lpae", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-cloud-amd64", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-cloud-arm64", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-common", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-common-rt", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-rt-686-pae", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-rt-amd64", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-rt-arm64", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-6.1.0-0.deb11.41-rt-armmp", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-686-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-686-pae-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-amd64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-amd64-signed-template", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-arm64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-arm64-signed-template", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-lpae", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-armmp-lpae-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-cloud-amd64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-cloud-arm64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-i386-signed-template", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-686-pae-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-amd64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-arm64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-armmp", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1-rt-armmp-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-686-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-686-pae-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-686-pae-unsigned", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-686-unsigned", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-amd64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-amd64-unsigned", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-arm64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-arm64-unsigned", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-armmp", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-armmp-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-armmp-lpae", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-armmp-lpae-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-cloud-amd64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-cloud-amd64-unsigned", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-cloud-arm64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-cloud-arm64-unsigned", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-rt-686-pae-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-rt-686-pae-unsigned", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-rt-amd64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-rt-amd64-unsigned", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-rt-arm64-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-rt-arm64-unsigned", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-rt-armmp", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.1.0-0.deb11.41-rt-armmp-dbg", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-6.1", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-6.1", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-6.1.0-0.deb11.41", ver:"6.1.158-1~deb11u1", rls:"DEB11"))) {
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
