# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7792.1");
  script_cve_id("CVE-2025-37756", "CVE-2025-37785", "CVE-2025-38477", "CVE-2025-38500", "CVE-2025-38618");
  script_tag(name:"creation_date", value:"2025-10-02 04:04:33 +0000 (Thu, 02 Oct 2025)");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-29 16:56:25 +0000 (Tue, 29 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7792-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7792-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7792-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gcp, linux-gcp-6.8, linux-gke, linux-gkeop, linux-ibm, linux-ibm-6.8, linux-lowlatency, linux-lowlatency-hwe-6.8, linux-nvidia, linux-nvidia-6.8, linux-nvidia-lowlatency' package(s) announced via the USN-7792-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Ext4 file system,
 - Network traffic control,
 - TLS protocol,
 - VMware vSockets driver,
 - XFRM subsystem,
(CVE-2025-38618, CVE-2025-38500, CVE-2025-37785, CVE-2025-38477,
CVE-2025-37756)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gcp, linux-gcp-6.8, linux-gke, linux-gkeop, linux-ibm, linux-ibm-6.8, linux-lowlatency, linux-lowlatency-hwe-6.8, linux-nvidia, linux-nvidia-6.8, linux-nvidia-lowlatency' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1038-ibm", ver:"6.8.0-1038.38~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1040-nvidia", ver:"6.8.0-1040.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1040-nvidia-64k", ver:"6.8.0-1040.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1041-gcp", ver:"6.8.0-1041.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1041-gcp-64k", ver:"6.8.0-1041.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-85-lowlatency", ver:"6.8.0-85.85.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-85-lowlatency-64k", ver:"6.8.0-85.85.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp", ver:"6.8.0-1041.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-6.8", ver:"6.8.0-1041.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k", ver:"6.8.0-1041.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k-6.8", ver:"6.8.0-1041.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm-6.8", ver:"6.8.0-1038.38~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-6.8", ver:"6.8.0-85.85.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-6.8", ver:"6.8.0-85.85.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-hwe-22.04", ver:"6.8.0-85.85.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-22.04", ver:"6.8.0-85.85.1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-6.8", ver:"6.8.0-1040.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-6.8", ver:"6.8.0-1040.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-hwe-22.04", ver:"6.8.0-1040.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-hwe-22.04", ver:"6.8.0-1040.43~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1024-gkeop", ver:"6.8.0-1024.26", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1037-gke", ver:"6.8.0-1037.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1037-gke-64k", ver:"6.8.0-1037.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1038-ibm", ver:"6.8.0-1038.38", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1040-aws", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1040-aws-64k", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1040-nvidia", ver:"6.8.0-1040.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1040-nvidia-64k", ver:"6.8.0-1040.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1040-nvidia-lowlatency", ver:"6.8.0-1040.43.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1040-nvidia-lowlatency-64k", ver:"6.8.0-1040.43.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1041-gcp", ver:"6.8.0-1041.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1041-gcp-64k", ver:"6.8.0-1041.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-85-generic", ver:"6.8.0-85.85", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-85-generic-64k", ver:"6.8.0-85.85", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-85-lowlatency", ver:"6.8.0-85.85.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-85-lowlatency-64k", ver:"6.8.0-85.85.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-6.8", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k-6.8", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-64k-lts-24.04", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws-lts-24.04", ver:"6.8.0-1040.42", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-6.8", ver:"6.8.0-1041.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k-6.8", ver:"6.8.0-1041.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-64k-lts-24.04", ver:"6.8.0-1041.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gcp-lts-24.04", ver:"6.8.0-1041.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"6.8.0-85.85", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-6.8", ver:"6.8.0-85.85", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k", ver:"6.8.0-85.85", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-64k-6.8", ver:"6.8.0-85.85", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"6.8.0-85.85", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke", ver:"6.8.0-1037.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-6.8", ver:"6.8.0-1037.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-64k", ver:"6.8.0-1037.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gke-64k-6.8", ver:"6.8.0-1037.41", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop", ver:"6.8.0-1024.26", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-gkeop-6.8", ver:"6.8.0-1024.26", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm", ver:"6.8.0-1038.38", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm-6.8", ver:"6.8.0-1038.38", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm-classic", ver:"6.8.0-1038.38", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-ibm-lts-24.04", ver:"6.8.0-1038.38", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"6.8.0-85.85", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"6.8.0-85.85.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-6.8", ver:"6.8.0-85.85.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k", ver:"6.8.0-85.85.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-64k-6.8", ver:"6.8.0-85.85.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia", ver:"6.8.0-1040.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-6.8", ver:"6.8.0-1040.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k", ver:"6.8.0-1040.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-64k-6.8", ver:"6.8.0-1040.43", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-lowlatency", ver:"6.8.0-1040.43.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-lowlatency-6.8", ver:"6.8.0-1040.43.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-lowlatency-64k", ver:"6.8.0-1040.43.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-nvidia-lowlatency-64k-6.8", ver:"6.8.0-1040.43.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"6.8.0-85.85", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-6.8", ver:"6.8.0-85.85", rls:"UBUNTU24.04 LTS"))) {
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
