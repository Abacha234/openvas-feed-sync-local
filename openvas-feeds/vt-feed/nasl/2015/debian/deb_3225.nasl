# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703225");
  script_cve_id("CVE-2015-0797");
  script_tag(name:"creation_date", value:"2015-04-14 22:00:00 +0000 (Tue, 14 Apr 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3225)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3225");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3225");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gst-plugins-bad0.10' package(s) announced via the DSA-3225 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aki Helin discovered a buffer overflow in the GStreamer plugin for MP4 playback, which could lead to the execution of arbitrary code.

For the stable distribution (wheezy), this problem has been fixed in version 0.10.23-7.1+deb7u2.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your gst-plugins-bad0.10 packages.");

  script_tag(name:"affected", value:"'gst-plugins-bad0.10' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);