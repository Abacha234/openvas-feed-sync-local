# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703342");
  script_cve_id("CVE-2015-5949");
  script_tag(name:"creation_date", value:"2015-08-19 22:00:00 +0000 (Wed, 19 Aug 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3342");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3342");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vlc' package(s) announced via the DSA-3342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Loren Maggiore of Trail of Bits discovered that the 3GP parser of VLC, a multimedia player and streamer, could dereference an arbitrary pointer due to insufficient restrictions on a writable buffer. This could allow remote attackers to execute arbitrary code via crafted 3GP files.

For the stable distribution (jessie), this problem has been fixed in version 2.2.0~rc2-2+deb8u1.

For the unstable distribution (sid), this problem will be fixed shortly.

We recommend that you upgrade your vlc packages.");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);