# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704203");
  script_cve_id("CVE-2017-17670");
  script_tag(name:"creation_date", value:"2018-05-16 22:00:00 +0000 (Wed, 16 May 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-26 15:11:00 +0000 (Fri, 26 Apr 2019)");

  script_name("Debian: Security Advisory (DSA-4203)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4203");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4203");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/vlc");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vlc' package(s) announced via the DSA-4203 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hans Jerry Illikainen discovered a type conversion vulnerability in the MP4 demuxer of the VLC media player, which could result in the execution of arbitrary code if a malformed media file is played.

This update upgrades VLC in stretch to the new 3.x release series (as security fixes couldn't be sensibly backported to the 2.x series). In addition two packages needed to be rebuild to ensure compatibility with VLC 3, phonon-backend-vlc (0.9.0-2+deb9u1) and goldencheetah (4.0.0~DEV1607-2+deb9u1).

VLC in jessie cannot be migrated to version 3 due to incompatible library changes with reverse dependencies and is thus now declared end-of-life for jessie. We recommend to upgrade to stretch or pick a different media player if that's not an option.

For the stable distribution (stretch), this problem has been fixed in version 3.0.2-0+deb9u1.

We recommend that you upgrade your vlc packages.

For the detailed security status of vlc please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);