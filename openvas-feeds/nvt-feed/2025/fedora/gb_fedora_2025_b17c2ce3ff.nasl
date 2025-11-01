# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9817992991013102102");
  script_cve_id("CVE-2025-22921");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-b17c2ce3ff)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-b17c2ce3ff");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-b17c2ce3ff");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2346558");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349351");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the FEDORA-2025-b17c2ce3ff advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for ffmpeg-7.1.1-1.fc43.

##### **Changelog**

```
* Thu Mar 6 2025 Dominik Mierzejewski <dominik@greysector.net> - 7.1.1-1
- Update to 7.1.1 (resolves rhbz#2349351)
- Enable LC3 codec via liblc3
- Backport fix for CVE-2025-22921 (resolves rhbz#2346558)

```");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-free", rpm:"ffmpeg-free~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-free-debuginfo", rpm:"ffmpeg-free-debuginfo~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-free-devel", rpm:"ffmpeg-free-devel~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-free", rpm:"libavcodec-free~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-free-debuginfo", rpm:"libavcodec-free-debuginfo~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-free-devel", rpm:"libavcodec-free-devel~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-free", rpm:"libavdevice-free~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-free-debuginfo", rpm:"libavdevice-free-debuginfo~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-free-devel", rpm:"libavdevice-free-devel~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-free", rpm:"libavfilter-free~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-free-debuginfo", rpm:"libavfilter-free-debuginfo~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-free-devel", rpm:"libavfilter-free-devel~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-free", rpm:"libavformat-free~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-free-debuginfo", rpm:"libavformat-free-debuginfo~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-free-devel", rpm:"libavformat-free-devel~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-free", rpm:"libavutil-free~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-free-debuginfo", rpm:"libavutil-free-debuginfo~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-free-devel", rpm:"libavutil-free-devel~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-free", rpm:"libpostproc-free~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-free-debuginfo", rpm:"libpostproc-free-debuginfo~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-free-devel", rpm:"libpostproc-free-devel~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-free", rpm:"libswresample-free~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-free-debuginfo", rpm:"libswresample-free-debuginfo~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-free-devel", rpm:"libswresample-free-devel~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-free", rpm:"libswscale-free~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-free-debuginfo", rpm:"libswscale-free-debuginfo~7.1.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-free-devel", rpm:"libswscale-free-devel~7.1.1~1.fc43", rls:"FC43"))) {
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
