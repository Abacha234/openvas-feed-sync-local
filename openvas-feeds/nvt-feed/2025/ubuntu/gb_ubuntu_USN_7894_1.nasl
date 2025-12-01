# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7894.1");
  script_cve_id("CVE-2021-3712", "CVE-2022-0778", "CVE-2022-4304", "CVE-2022-4450", "CVE-2023-0215", "CVE-2023-0286", "CVE-2023-0464", "CVE-2023-0465", "CVE-2023-0466", "CVE-2023-2650", "CVE-2023-3446", "CVE-2023-3817", "CVE-2023-45236", "CVE-2023-45237", "CVE-2023-5678", "CVE-2023-6237", "CVE-2024-0727", "CVE-2024-1298", "CVE-2024-13176", "CVE-2024-2511", "CVE-2024-38796", "CVE-2024-38797", "CVE-2024-38805", "CVE-2024-4741", "CVE-2024-5535", "CVE-2024-6119", "CVE-2024-9143", "CVE-2025-2295", "CVE-2025-3770", "CVE-2025-9232");
  script_tag(name:"creation_date", value:"2025-11-28 04:06:10 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T05:40:45+0000");
  script_tag(name:"last_modification", value:"2025-11-28 05:40:45 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-03 10:51:54 +0000 (Tue, 03 Jun 2025)");

  script_name("Ubuntu: Security Advisory (USN-7894-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7894-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7894-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'edk2' package(s) announced via the USN-7894-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that EDK II was susceptible to a predictable TCP Initial
Sequence Number. An attacker could possibly use this issue to gain
unauthorized access. This issue only affected Ubuntu 22.04 LTS, and Ubuntu
24.04 LTS. (CVE-2023-45236, CVE-2023-45237)

It was discovered that EDK II incorrectly handled S3 sleep. An attacker
could possibly use this issue to cause a denial of service. This issue only
affected Ubuntu 22.04 LTS, and Ubuntu 24.04 LTS. (CVE-2024-1298)

It was discovered that the EDK II PE/COFF loader incorrectly handled
certain memory operations. An attacker could possibly use this issue to
cause a denial of service, obtain sensitive information, or execute
arbitrary code. This issue only affected Ubuntu 22.04 LTS, and Ubuntu
24.04 LTS. (CVE-2024-38796)

It was discovered that the EDK II PE image hashing function incorrectly
handled certain memory operations. An attacker could possibly use this
issue to cause a denial of service, or execute arbitrary code.
(CVE-2024-38797)

It was discovered that the EDK II BIOS incorrectly handled certain memory
operations. An attacker could possibly use this issue to cause a denial of
service. (CVE-2024-38805, CVE-2025-2295)

It was discovered that EDK II incorrectly handled the enabling of MCE. An
attacker could possibly use this issue to cause a denial of service, or
execute arbitrary code. (CVE-2025-3770)

It was discovered that the OpenSSL library embedded in EDK II contained
multiple vulnerabilties. An attacker could possibly use these issues to
cause a denial of service, obtain sensitive information, or execute
arbitrary code. (CVE-2021-3712, CVE-2022-0778, CVE-2022-4304,
CVE-2022-4450, CVE-2023-0215, CVE-2023-0286, CVE-2023-0464, CVE-2023-0465,
CVE-2023-0466, CVE-2023-2650, CVE-2023-3446, CVE-2023-3817, CVE-2023-5678,
CVE-2023-6237, CVE-2024-0727, CVE-2024-13176, CVE-2024-2511,
CVE-2024-41996, CVE-2024-4741, CVE-2024-5535, CVE-2024-6119, CVE-2024-9143,
CVE-2025-9232)");

  script_tag(name:"affected", value:"'edk2' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"2022.02-3ubuntu0.22.04.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovmf-ia32", ver:"2022.02-3ubuntu0.22.04.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi", ver:"2022.02-3ubuntu0.22.04.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"2022.02-3ubuntu0.22.04.4", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"2022.02-3ubuntu0.22.04.4", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"2024.02-2ubuntu0.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovmf-ia32", ver:"2024.02-2ubuntu0.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"2024.02-2ubuntu0.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"2024.02-2ubuntu0.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-riscv64", ver:"2024.02-2ubuntu0.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"ovmf", ver:"2025.02-3ubuntu2.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ovmf-ia32", ver:"2025.02-3ubuntu2.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-aarch64", ver:"2025.02-3ubuntu2.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-arm", ver:"2025.02-3ubuntu2.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-loongarch64", ver:"2025.02-3ubuntu2.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-efi-riscv64", ver:"2025.02-3ubuntu2.2", rls:"UBUNTU25.04"))) {
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
