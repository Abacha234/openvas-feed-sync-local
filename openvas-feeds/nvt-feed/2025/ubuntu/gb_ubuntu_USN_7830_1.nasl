# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7830.1");
  script_cve_id("CVE-2023-6603", "CVE-2023-6605", "CVE-2025-10256", "CVE-2025-7700", "CVE-2025-9951");
  script_tag(name:"creation_date", value:"2025-10-23 04:05:14 +0000 (Thu, 23 Oct 2025)");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-31 15:15:07 +0000 (Tue, 31 Dec 2024)");

  script_name("Ubuntu: Security Advisory (USN-7830-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7830-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7830-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the USN-7830-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FFmpeg incorrectly handled the return values of
functions in its Firequalizer filter and in the HTTP Live Streaming (HLS)
implementation, leading to a NULL pointer dereference. If a user was
tricked into loading a crafted media file, a remote attacker could
possibly use this issue to make FFmpeg crash, resulting in a denial
of service. (CVE-2023-6603, CVE-2025-10256)

It was discovered that FFmpeg did not enforce an input format before
triggering the HTTP demuxer. A remote attacker could possibly use this
issue to perform a Server-Side Request Forgery (SSRF) attack.
(CVE-2025-6605)

It was discovered that FFmpeg incorrectly handled memory allocation in the
ALS audio decoder. If a user was tricked into loading a crafted media file,
a remote attacker could possibly use this issue to make FFmpeg crash,
resulting in a denial of service. (CVE-2025-7700)

It was discovered that FFmpeg incorrectly handled memory in the JPEG 2000
decoder, which could lead to a heap buffer overflow. If a user or
application were tricked into opening a specially crafted file, an
attacker could possibly use this issue to cause a denial of service
or leak sensitive information. (CVE-2025-9951)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:3.4.11-0ubuntu0.1+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec57", ver:"7:3.4.11-0ubuntu0.1+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat57", ver:"7:3.4.11-0ubuntu0.1+esm11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:4.2.7-0ubuntu0.1+esm11", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec58", ver:"7:4.2.7-0ubuntu0.1+esm11", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat58", ver:"7:4.2.7-0ubuntu0.1+esm11", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:4.4.2-0ubuntu0.22.04.1+esm10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec58", ver:"7:4.4.2-0ubuntu0.22.04.1+esm10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat58", ver:"7:4.4.2-0ubuntu0.22.04.1+esm10", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:6.1.1-3ubuntu5+esm6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec60", ver:"7:6.1.1-3ubuntu5+esm6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat60", ver:"7:6.1.1-3ubuntu5+esm6", rls:"UBUNTU24.04 LTS"))) {
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
