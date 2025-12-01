# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0306");
  script_cve_id("CVE-2023-50007", "CVE-2023-50008", "CVE-2023-6602", "CVE-2023-6604", "CVE-2023-6605", "CVE-2024-31582", "CVE-2024-35367", "CVE-2025-59728", "CVE-2025-59731", "CVE-2025-59732", "CVE-2025-59733", "CVE-2025-7700");
  script_tag(name:"creation_date", value:"2025-11-24 04:18:19 +0000 (Mon, 24 Nov 2025)");
  script_version("2025-11-24T05:41:47+0000");
  script_tag(name:"last_modification", value:"2025-11-24 05:41:47 +0000 (Mon, 24 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-07 19:16:27 +0000 (Fri, 07 Nov 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0306)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0306");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0306.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34757");
  script_xref(name:"URL", value:"https://ffmpeg.org/security.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2025/msg00149.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the MGASA-2025-0306 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FFmpeg v.n6.1-3-g466799d4f5 allows an attacker to trigger use of a
parameter of negative size in the av_samples_set_silence function in
thelibavutil/samplefmt.c:260:9 component. (CVE-2023-50007)
FFmpeg v.n6.1-3-g466799d4f5 allows memory consumption when using the
colorcorrect filter, in the av_malloc function in libavutil/mem.c:105:9
component. (CVE-2023-50008)
Improper handling of input format in tty demuxer of ffmpeg.
(CVE-2023-6602)
Hls xbin demuxer dos amplification in ffmpeg. (CVE-2023-6604)
Dash playlist ssrf vulnerability in ffmpeg. (CVE-2023-6605)
FFmpeg version n6.1 was discovered to contain a heap buffer overflow
vulnerability in the draw_block_rectangle function of
libavfilter/vf_codecview.c. This vulnerability allows attackers to cause
undefined behavior or a Denial of Service (DoS) via crafted input.
(CVE-2024-31582)
FFmpeg n6.1.1 has an Out-of-bounds Read via
libavcodec/ppc/vp8dsp_altivec.c, static const vec_s8
h_subpel_filters_outer. (CVE-2024-35367)
Heap-buffer-overflow write in FFmpeg MDASH resolve_content_path.
(CVE-2025-59728)
Heap-buffer-overflow write in FFmpeg EXR dwa_uncompress.
(CVE-2025-59731, CVE-2025-59732, CVE-2025-59733)
Null pointer dereference in ffmpeg als decoder (libavcodec/alsdec.c).
(CVE-2025-7700)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec59", rpm:"lib64avcodec59~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec59", rpm:"lib64avcodec59~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter8", rpm:"lib64avfilter8~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter8", rpm:"lib64avfilter8~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat59", rpm:"lib64avformat59~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat59", rpm:"lib64avformat59~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil57", rpm:"lib64avutil57~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil57", rpm:"lib64avutil57~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc56", rpm:"lib64postproc56~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc56", rpm:"lib64postproc56~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample4", rpm:"lib64swresample4~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample4", rpm:"lib64swresample4~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler6", rpm:"lib64swscaler6~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler6", rpm:"lib64swscaler6~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec59", rpm:"libavcodec59~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec59", rpm:"libavcodec59~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter8", rpm:"libavfilter8~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter8", rpm:"libavfilter8~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat59", rpm:"libavformat59~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat59", rpm:"libavformat59~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil57", rpm:"libavutil57~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil57", rpm:"libavutil57~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc56", rpm:"libpostproc56~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc56", rpm:"libpostproc56~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample4", rpm:"libswresample4~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample4", rpm:"libswresample4~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler6", rpm:"libswscaler6~5.1.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler6", rpm:"libswscaler6~5.1.7~1.mga9.tainted", rls:"MAGEIA9"))) {
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
