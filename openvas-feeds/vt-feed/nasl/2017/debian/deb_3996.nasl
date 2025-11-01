# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703996");
  script_cve_id("CVE-2017-14054", "CVE-2017-14055", "CVE-2017-14056", "CVE-2017-14057", "CVE-2017-14058", "CVE-2017-14059", "CVE-2017-14169", "CVE-2017-14170", "CVE-2017-14171", "CVE-2017-14222", "CVE-2017-14223", "CVE-2017-14225", "CVE-2017-14767");
  script_tag(name:"creation_date", value:"2017-10-09 22:00:00 +0000 (Mon, 09 Oct 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-05 17:55:00 +0000 (Tue, 05 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-3996)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3996");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3996");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ffmpeg' package(s) announced via the DSA-3996 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the FFmpeg multimedia framework, which could result in denial of service or potentially the execution of arbitrary code if malformed Real, MV, RL2, ASF, Apple HLS, Phantom Cine, MXF, NSV, MOV or RTP H.264 files/streams are processed.

For the stable distribution (stretch), these problems have been fixed in version 7:3.2.8-1~deb9u1.

We recommend that you upgrade your ffmpeg packages.");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);