# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7890.1");
  script_cve_id("CVE-2023-6603");
  script_tag(name:"creation_date", value:"2025-11-28 08:37:19 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T15:41:52+0000");
  script_tag(name:"last_modification", value:"2025-11-28 15:41:52 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-31 15:15:07 +0000 (Tue, 31 Dec 2024)");

  script_name("Ubuntu: Security Advisory (USN-7890-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7890-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7890-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the USN-7890-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FFmpeg did not properly handle the parsing of
certain malformed HLS playlists. If a user were tricked into opening a
specially crafted HLS playlist, an attacker could possibly use this issue
to cause FFmpeg to crash, resulting in a denial of service.");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:2.8.17-0ubuntu0.1+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-ffmpeg-extra56", ver:"7:2.8.17-0ubuntu0.1+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-ffmpeg56", ver:"7:2.8.17-0ubuntu0.1+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice-ffmpeg56", ver:"7:2.8.17-0ubuntu0.1+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-ffmpeg5", ver:"7:2.8.17-0ubuntu0.1+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-ffmpeg56", ver:"7:2.8.17-0ubuntu0.1+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil-ffmpeg54", ver:"7:2.8.17-0ubuntu0.1+esm13", rls:"UBUNTU16.04 LTS"))) {
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
