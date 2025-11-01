# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703591");
  script_cve_id("CVE-2016-5118");
  script_tag(name:"creation_date", value:"2016-05-31 22:00:00 +0000 (Tue, 31 May 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Debian: Security Advisory (DSA-3591)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3591");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3591");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-3591 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bob Friesenhahn from the GraphicsMagick project discovered a command injection vulnerability in ImageMagick, a program suite for image manipulation. An attacker with control on input image or the input filename can execute arbitrary commands with the privileges of the user running the application.

This update removes the possibility of using pipe (<pipe>) in filenames to interact with imagemagick.

It is important that you upgrade the libmagickcore-6.q16-2 and not just the imagemagick package. Applications using libmagickcore-6.q16-2 might also be affected and need to be restarted after the upgrade.

For the stable distribution (jessie), this problem has been fixed in version 8:6.8.9.9-5+deb8u3.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);