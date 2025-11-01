# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844502");
  script_cve_id("CVE-2018-15822", "CVE-2019-11338", "CVE-2019-12730", "CVE-2019-13312", "CVE-2019-13390", "CVE-2019-17539", "CVE-2019-17542", "CVE-2020-12284", "CVE-2020-13904");
  script_tag(name:"creation_date", value:"2020-07-23 03:00:56 +0000 (Thu, 23 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 21:15:00 +0000 (Mon, 04 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-4431-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4431-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4431-1");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3967-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the USN-4431-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that FFmpeg incorrectly verified empty audio packets or
HEVC data. An attacker could possibly use this issue to cause a denial of
service via a crafted file. This issue only affected Ubuntu 16.04 LTS, as
it was already fixed in Ubuntu 18.04 LTS. For more information see:
[link moved to references]
(CVE-2018-15822, CVE-2019-11338)

It was discovered that FFmpeg incorrectly handled sscanf failures. An
attacker could possibly use this issue to cause a denial of service or
other unspecified impact. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 18.04 LTS. (CVE-2019-12730)

It was discovered that FFmpeg incorrectly handled certain WEBM files. An
attacker could possibly use this issue to obtain sensitive data or other
unspecified impact. This issue only affected Ubuntu 20.04 LTS.
(CVE-2019-13312)

It was discovered that FFmpeg incorrectly handled certain AVI files. An
attacker could possibly use this issue to cause a denial of service or
other unspecified impact. This issue only affected Ubuntu 16.04 LTS and
Ubuntu 18.04 LTS. (CVE-2019-13390)

It was discovered that FFmpeg incorrectly handled certain input. An
attacker could possibly use this issue to cause a denial of service or
other unspecified impact. This issue only affected Ubuntu 18.04 LTS.
(CVE-2019-17539)

It was discovered that FFmpeg incorrectly handled certain input during
decoding of VQA files. An attacker could possibly use this issue to
obtain sensitive information or other unspecified impact. This issue
only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2019-17542)

It was discovered that FFmpeg incorrectly handled certain JPEG files. An
attacker could possibly use this issue to obtain sensitive information
or other unspecified impact. This issue only affected Ubuntu 20.04 LTS.
(CVE-2020-12284)

It was discovered that FFmpeg incorrectly handled certain M3U8 files. An
attacker could possibly use this issue to obtain sensitive information
or other unspecified impact. (CVE-2020-13904)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
