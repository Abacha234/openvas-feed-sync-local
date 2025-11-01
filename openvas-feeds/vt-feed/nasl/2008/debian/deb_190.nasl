# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53853");
  script_cve_id("CVE-2002-1277");
  script_tag(name:"creation_date", value:"2008-01-17 21:24:46 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-190)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-190");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/dsa-190");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wmaker' package(s) announced via the DSA-190 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Al Viro found a problem in the image handling code use in Window Maker, a popular NEXTSTEP like window manager. When creating an image it would allocate a buffer by multiplying the image width and height, but did not check for an overflow. This makes it possible to overflow the buffer. This could be exploited by using specially crafted image files (for example when previewing themes).

This problem has been fixed in version 0.80.0-4.1 for the current stable distribution (woody). Packages for the mipsel architecture are not yet available.");

  script_tag(name:"affected", value:"'wmaker' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);