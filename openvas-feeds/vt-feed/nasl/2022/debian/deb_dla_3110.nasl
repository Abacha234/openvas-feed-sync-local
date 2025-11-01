# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893110");
  script_cve_id("CVE-2021-3800");
  script_tag(name:"creation_date", value:"2022-09-16 01:00:08 +0000 (Fri, 16 Sep 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-30 15:39:00 +0000 (Tue, 30 Aug 2022)");

  script_name("Debian: Security Advisory (DLA-3110)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3110");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3110");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/glib2.0");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'glib2.0' package(s) announced via the DLA-3110 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that GLib, a general-purpose portable utility library, could be used to print partial contents from arbitrary files. This could be exploited from setuid binaries linking to GLib for information disclosure of files with a specific format.

For Debian 10 buster, this problem has been fixed in version 2.58.3-2+deb10u4.

We recommend that you upgrade your glib2.0 packages.

For the detailed security status of glib2.0 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);