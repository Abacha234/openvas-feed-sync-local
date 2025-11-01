# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703821");
  script_cve_id("CVE-2017-5846", "CVE-2017-5847");
  script_tag(name:"creation_date", value:"2017-03-26 22:00:00 +0000 (Sun, 26 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-20 19:01:00 +0000 (Fri, 20 Nov 2020)");

  script_name("Debian: Security Advisory (DSA-3821)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3821");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3821");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gst-plugins-ugly1.0' package(s) announced via the DSA-3821 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hanno Boeck discovered multiple vulnerabilities in the GStreamer media framework and its codecs and demuxers, which may result in denial of service or the execution of arbitrary code if a malformed media file is opened.

For the stable distribution (jessie), these problems have been fixed in version 1.4.4-2+deb8u1.

For the upcoming stable distribution (stretch), these problems have been fixed in version 1.10.4-1.

For the unstable distribution (sid), these problems have been fixed in version 1.10.4-1.

We recommend that you upgrade your gst-plugins-ugly1.0 packages.");

  script_tag(name:"affected", value:"'gst-plugins-ugly1.0' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);