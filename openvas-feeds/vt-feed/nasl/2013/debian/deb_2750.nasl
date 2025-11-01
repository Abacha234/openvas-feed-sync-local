# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702750");
  script_cve_id("CVE-2013-4298");
  script_tag(name:"creation_date", value:"2013-09-02 22:00:00 +0000 (Mon, 02 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2750)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2750");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2750");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imagemagick' package(s) announced via the DSA-2750 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Anton Kortunov reported a heap corruption in ImageMagick, a program collection and library for converting and manipulating image files. Crafted GIF files could cause ImageMagick to crash, potentially leading to arbitrary code execution.

The oldstable distribution (squeeze) is not affected by this problem.

For the stable distribution (wheezy), this problem has been fixed in version 8:6.7.7.10-5+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 8:6.7.7.10-6.

We recommend that you upgrade your imagemagick packages.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);