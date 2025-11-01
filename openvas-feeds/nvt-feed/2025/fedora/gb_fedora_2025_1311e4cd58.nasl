# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.131110149910058");
  script_tag(name:"creation_date", value:"2025-10-28 15:26:41 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-1311e4cd58)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-1311e4cd58");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-1311e4cd58");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2352783");
  script_xref(name:"URL", value:"https://github.com/zip-rs/zip2/security/advisories/GHSA-94vh-gphv-8pm8");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-uv-build, rust-gitui, rust-gstreamer, rust-ron, rust-version-ranges, rust-zip, uv' package(s) announced via the FEDORA-2025-1311e4cd58 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update rust-ron to 0.9.

Update rust-zip to 2.6.1, fixing [GHSA-94vh-gphv-8pm8]([link moved to references]).");

  script_tag(name:"affected", value:"'python-uv-build, rust-gitui, rust-gstreamer, rust-ron, rust-version-ranges, rust-zip, uv' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"gitui", rpm:"gitui~0.26.3~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gitui-debuginfo", rpm:"gitui-debuginfo~0.26.3~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build", rpm:"python-uv-build~0.6.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-uv-build-debugsource", rpm:"python-uv-build-debugsource~0.6.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv", rpm:"python3-uv~0.6.14~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build", rpm:"python3-uv-build~0.6.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-uv-build-debuginfo", rpm:"python3-uv-build-debuginfo~0.6.14~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gitui", rpm:"rust-gitui~0.26.3~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gitui-debugsource", rpm:"rust-gitui-debugsource~0.26.3~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+default-devel", rpm:"rust-gstreamer+default-devel~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+log-devel", rpm:"rust-gstreamer+log-devel~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+serde-devel", rpm:"rust-gstreamer+serde-devel~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+serde_bytes-devel", rpm:"rust-gstreamer+serde_bytes-devel~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+v1_16-devel", rpm:"rust-gstreamer+v1_16-devel~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+v1_18-devel", rpm:"rust-gstreamer+v1_18-devel~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+v1_20-devel", rpm:"rust-gstreamer+v1_20-devel~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+v1_22-devel", rpm:"rust-gstreamer+v1_22-devel~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer+v1_24-devel", rpm:"rust-gstreamer+v1_24-devel~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer", rpm:"rust-gstreamer~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gstreamer-devel", rpm:"rust-gstreamer-devel~0.23.5~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ron+default-devel", rpm:"rust-ron+default-devel~0.9.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ron+indexmap-devel", rpm:"rust-ron+indexmap-devel~0.9.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ron+integer128-devel", rpm:"rust-ron+integer128-devel~0.9.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ron", rpm:"rust-ron~0.9.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-ron-devel", rpm:"rust-ron-devel~0.9.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-version-ranges+default-devel", rpm:"rust-version-ranges+default-devel~0.1.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-version-ranges+proptest-devel", rpm:"rust-version-ranges+proptest-devel~0.1.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-version-ranges+serde-devel", rpm:"rust-version-ranges+serde-devel~0.1.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-version-ranges", rpm:"rust-version-ranges~0.1.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-version-ranges-devel", rpm:"rust-version-ranges-devel~0.1.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+_all-features-devel", rpm:"rust-zip+_all-features-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+_deflate-any-devel", rpm:"rust-zip+_deflate-any-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+aes-crypto-devel", rpm:"rust-zip+aes-crypto-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+aes-devel", rpm:"rust-zip+aes-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+bzip2-devel", rpm:"rust-zip+bzip2-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+chrono-devel", rpm:"rust-zip+chrono-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+constant_time_eq-devel", rpm:"rust-zip+constant_time_eq-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+default-devel", rpm:"rust-zip+default-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-devel", rpm:"rust-zip+deflate-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-flate2-devel", rpm:"rust-zip+deflate-flate2-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-miniz-devel", rpm:"rust-zip+deflate-miniz-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-zlib-devel", rpm:"rust-zip+deflate-zlib-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-zlib-ng-devel", rpm:"rust-zip+deflate-zlib-ng-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate-zopfli-devel", rpm:"rust-zip+deflate-zopfli-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+deflate64-devel", rpm:"rust-zip+deflate64-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+flate2-devel", rpm:"rust-zip+flate2-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+getrandom-devel", rpm:"rust-zip+getrandom-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+hmac-devel", rpm:"rust-zip+hmac-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+jiff-02-devel", rpm:"rust-zip+jiff-02-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+lzma-devel", rpm:"rust-zip+lzma-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+lzma-rs-devel", rpm:"rust-zip+lzma-rs-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+pbkdf2-devel", rpm:"rust-zip+pbkdf2-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+proc-macro2-devel", rpm:"rust-zip+proc-macro2-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+sha1-devel", rpm:"rust-zip+sha1-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+time-devel", rpm:"rust-zip+time-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+unreserved-devel", rpm:"rust-zip+unreserved-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+xz-devel", rpm:"rust-zip+xz-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+zeroize-devel", rpm:"rust-zip+zeroize-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+zopfli-devel", rpm:"rust-zip+zopfli-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip+zstd-devel", rpm:"rust-zip+zstd-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip", rpm:"rust-zip~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zip-devel", rpm:"rust-zip-devel~2.6.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv", rpm:"uv~0.6.14~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debuginfo", rpm:"uv-debuginfo~0.6.14~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uv-debugsource", rpm:"uv-debugsource~0.6.14~3.fc43", rls:"FC43"))) {
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
