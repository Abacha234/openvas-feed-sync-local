# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844112");
  script_cve_id("CVE-2018-19857", "CVE-2019-12874", "CVE-2019-13602", "CVE-2019-5439");
  script_tag(name:"creation_date", value:"2019-07-26 02:00:57 +0000 (Fri, 26 Jul 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-25 12:15:00 +0000 (Tue, 25 Jun 2019)");

  script_name("Ubuntu: Security Advisory (USN-4074-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4074-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4074-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc' package(s) announced via the USN-4074-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the VLC CAF demuxer incorrectly handled certain
files. If a user were tricked into opening a specially-crafted CAF file, a
remote attacker could use this issue to cause VLC to crash, resulting in a
denial of service. This issue only affected Ubuntu 18.04 LTS.
(CVE-2018-19857)

It was discovered that the VLC Matroska demuxer incorrectly handled certain
files. If a user were tricked into opening a specially-crafted MKV file, a
remote attacker could use this issue to cause VLC to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2019-12874)

It was discovered that the VLC MP4 demuxer incorrectly handled certain
files. If a user were tricked into opening a specially-crafted MP4 file, a
remote attacker could use this issue to cause VLC to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2019-13602)

It was discovered that the VLC AVI demuxer incorrectly handled certain
files. If a user were tricked into opening a specially-crafted AVI file, a
remote attacker could use this issue to cause VLC to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2019-5439)");

  script_tag(name:"affected", value:"'vlc' package(s) on Ubuntu 18.04, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
