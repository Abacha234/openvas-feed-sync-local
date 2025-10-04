# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.4810099569910248");
  script_cve_id("CVE-2025-1373", "CVE-2025-22919", "CVE-2025-25469", "CVE-2025-25473");
  script_tag(name:"creation_date", value:"2025-10-03 04:07:21 +0000 (Fri, 03 Oct 2025)");
  script_version("2025-10-03T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-10-03 15:40:40 +0000 (Fri, 03 Oct 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-03 17:53:41 +0000 (Tue, 03 Jun 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-48dc56cf48)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-48dc56cf48");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-48dc56cf48");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2346103");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2346574");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2346583");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2346591");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the FEDORA-2025-48dc56cf48 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 7.1.2.");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-free", rpm:"ffmpeg-free~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-free-debuginfo", rpm:"ffmpeg-free-debuginfo~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-free-devel", rpm:"ffmpeg-free-devel~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-free", rpm:"libavcodec-free~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-free-debuginfo", rpm:"libavcodec-free-debuginfo~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-free-devel", rpm:"libavcodec-free-devel~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-free", rpm:"libavdevice-free~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-free-debuginfo", rpm:"libavdevice-free-debuginfo~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-free-devel", rpm:"libavdevice-free-devel~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-free", rpm:"libavfilter-free~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-free-debuginfo", rpm:"libavfilter-free-debuginfo~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-free-devel", rpm:"libavfilter-free-devel~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-free", rpm:"libavformat-free~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-free-debuginfo", rpm:"libavformat-free-debuginfo~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-free-devel", rpm:"libavformat-free-devel~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-free", rpm:"libavutil-free~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-free-debuginfo", rpm:"libavutil-free-debuginfo~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-free-devel", rpm:"libavutil-free-devel~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-free", rpm:"libpostproc-free~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-free-debuginfo", rpm:"libpostproc-free-debuginfo~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-free-devel", rpm:"libpostproc-free-devel~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-free", rpm:"libswresample-free~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-free-debuginfo", rpm:"libswresample-free-debuginfo~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-free-devel", rpm:"libswresample-free-devel~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-free", rpm:"libswscale-free~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-free-debuginfo", rpm:"libswscale-free-debuginfo~7.1.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-free-devel", rpm:"libswscale-free-devel~7.1.2~1.fc41", rls:"FC41"))) {
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
