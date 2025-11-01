# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703994");
  script_cve_id("CVE-2017-14604");
  script_tag(name:"creation_date", value:"2017-10-06 22:00:00 +0000 (Fri, 06 Oct 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-3994)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3994");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3994");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nautilus' package(s) announced via the DSA-3994 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Boxdorfer discovered a vulnerability in the handling of FreeDesktop.org .desktop files in Nautilus, a file manager for the GNOME desktop environment. An attacker can craft a .desktop file intended to run malicious commands but displayed as a innocuous document file in Nautilus. An user would then trust it and open the file, and Nautilus would in turn execute the malicious content. Nautilus protection of only trusting .desktop files with executable permission can be bypassed by shipping the .desktop file inside a tarball.

For the oldstable distribution (jessie), this problem has not been fixed yet.

For the stable distribution (stretch), this problem has been fixed in version 3.22.3-1+deb9u1.

For the testing distribution (buster), this problem has been fixed in version 3.26.0-1.

For the unstable distribution (sid), this problem has been fixed in version 3.26.0-1.

We recommend that you upgrade your nautilus packages.");

  script_tag(name:"affected", value:"'nautilus' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);