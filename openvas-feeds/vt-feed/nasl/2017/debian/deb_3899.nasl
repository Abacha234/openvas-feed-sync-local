# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703899");
  script_cve_id("CVE-2017-8310", "CVE-2017-8311", "CVE-2017-8312", "CVE-2017-8313");
  script_tag(name:"creation_date", value:"2017-06-26 22:00:00 +0000 (Mon, 26 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-27 01:29:00 +0000 (Fri, 27 Apr 2018)");

  script_name("Debian: Security Advisory (DSA-3899)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3899");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3899");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vlc' package(s) announced via the DSA-3899 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in VLC, the VideoLAN project's media player. Processing malformed subtitles or movie files could lead to denial of service and potentially the execution of arbitrary code.

For the oldstable distribution (jessie), these problems have been fixed in version 2.2.6-1~deb8u1.

We recommend that you upgrade your vlc packages.");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);