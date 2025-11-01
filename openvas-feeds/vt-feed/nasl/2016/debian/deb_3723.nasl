# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703723");
  script_cve_id("CVE-2016-9634", "CVE-2016-9635", "CVE-2016-9636");
  script_tag(name:"creation_date", value:"2016-11-23 23:00:00 +0000 (Wed, 23 Nov 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3723)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3723");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3723");
  script_xref(name:"URL", value:"https://scarybeastsecurity.blogspot.de/2016/11/0day-exploit-advancing-exploitation.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gst-plugins-good1.0' package(s) announced via the DSA-3723 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Evans discovered that the GStreamer 1.0 plugin used to decode files in the FLIC format allowed execution of arbitrary code. Further details can be found in his advisory at [link moved to references]

For the stable distribution (jessie), these problems have been fixed in version 1.4.4-2+deb8u2.

For the unstable distribution (sid), these problems have been fixed in version 1.10.1-2.

We recommend that you upgrade your gst-plugins-good1.0 packages.");

  script_tag(name:"affected", value:"'gst-plugins-good1.0' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);