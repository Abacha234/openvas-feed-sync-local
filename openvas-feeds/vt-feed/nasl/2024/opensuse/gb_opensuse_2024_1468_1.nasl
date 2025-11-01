# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856118");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-20894", "CVE-2020-20898", "CVE-2020-20900", "CVE-2020-20901", "CVE-2021-38090", "CVE-2021-38091", "CVE-2021-38094", "CVE-2023-49502", "CVE-2024-31578");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-23 15:09:44 +0000 (Thu, 23 Sep 2021)");
  script_tag(name:"creation_date", value:"2024-05-07 01:05:47 +0000 (Tue, 07 May 2024)");
  script_name("openSUSE: Security Advisory for ffmpeg (SUSE-SU-2024:1468-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1468-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3HNOABOFC373ET7YWPU3ZXKFPLK65P4J");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the SUSE-SU-2024:1468-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg fixes the following issues:

  * CVE-2024-31578: Fixed heap use-after-free via av_hwframe_ctx_init() when
      vulkan_frames init failed (bsc#1223070)

  * CVE-2023-49502: Fixed heap buffer overflow via the ff_bwdif_filter_intra_c
      function in libavfilter/bwdifdsp.c (bsc#1223235)

  Adding references for already fixed issues:

  * CVE-2021-38091: Fixed integer overflow in function filter16_sobel in
      libavfilter/vf_convolution.c (bsc#1190732)

  * CVE-2021-38090: Fixed integer overflow in function filter16_roberts in
      libavfilter/vf_convolution.c (bsc#1190731)

  * CVE-2020-20898: Fixed integer overflow vulnerability in function
      filter16_prewitt in libavfilter/vf_convolution.c (bsc#1190724)

  * CVE-2020-20901: Fixed buffer overflow vulnerability in function filter_frame
      in libavfilter/vf_fieldorder.c (bsc#1190728)

  * CVE-2020-20900: Fixed buffer overflow vulnerability in function
      gaussian_blur in libavfilter/vf_edgedetect.c (bsc#1190727)

  * CVE-2020-20894: Fixed buffer Overflow vulnerability in function
      gaussian_blur in libavfilter/vf_edgedetect.c (bsc#1190721)

  ##");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
