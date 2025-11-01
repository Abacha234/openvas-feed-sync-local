# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703783");
  script_cve_id("CVE-2016-10158", "CVE-2016-10159", "CVE-2016-10160", "CVE-2016-10161", "CVE-2016-7479");
  script_tag(name:"creation_date", value:"2017-02-07 23:00:00 +0000 (Tue, 07 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-04 01:29:00 +0000 (Fri, 04 May 2018)");

  script_name("Debian: Security Advisory (DSA-3783)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3783");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3783");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-3783 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in PHP, a widely-used open source general-purpose scripting language.

CVE-2016-10158

Loading a TIFF or JPEG malicious file can lead to a Denial-of-Service attack when the EXIF header is being parsed.

CVE-2016-10159

Loading a malicious phar archive can cause an extensive memory allocation, leading to a Denial-of-Service attack on 32 bit computers.

CVE-2016-10160

An attacker might remotely execute arbitrary code using a malicious phar archive. This is the consequence of an off-by-one memory corruption.

CVE-2016-10161

An attacker with control of the unserialize() function argument can cause an out-of-bounce read. This could lead to a Denial-of-Service attack or a remote code execution.

For the stable distribution (jessie), these problems have been fixed in version 5.6.30+dfsg-0+deb8u1.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);