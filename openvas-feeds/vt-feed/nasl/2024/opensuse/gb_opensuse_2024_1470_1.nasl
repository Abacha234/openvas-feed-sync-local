# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856119");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-49502", "CVE-2023-51793", "CVE-2024-31578");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-05-07 01:05:53 +0000 (Tue, 07 May 2024)");
  script_name("openSUSE: Security Advisory for ffmpeg (SUSE-SU-2024:1470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1470-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WDRH3D23AEQTANH4C6FV36DHK3YGQ5LZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the SUSE-SU-2024:1470-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg-4 fixes the following issues:

  * CVE-2024-31578: Fixed heap use-after-free via av_hwframe_ctx_init() when
      vulkan_frames init failed (bsc#1223070)

  * CVE-2023-49502: Fixed heap buffer overflow via the ff_bwdif_filter_intra_c
      function in libavfilter/bwdifdsp.c (bsc#1223235)

  * CVE-2023-51793: Fixed heap buffer overflow in the image_copy_plane function
      in libavutil/imgutils.c (bsc#1223272)

  ##");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
