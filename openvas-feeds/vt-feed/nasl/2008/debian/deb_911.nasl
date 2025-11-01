# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55941");
  script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-911)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-911");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-911");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gtk+2.0' package(s) announced via the DSA-911 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in gtk+2.0, the Gtk+ GdkPixBuf XPM image rendering library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-2975

Ludwig Nussel discovered an infinite loop when processing XPM images that allows an attacker to cause a denial of service via a specially crafted XPM file.

CVE-2005-2976

Ludwig Nussel discovered an integer overflow in the way XPM images are processed that could lead to the execution of arbitrary code or crash the application via a specially crafted XPM file.

CVE-2005-3186

'infamous41md' discovered an integer overflow in the XPM processing routine that can be used to execute arbitrary code via a traditional heap overflow.

The following matrix explains which versions fix these problems:



old stable (woody)

stable (sarge)

unstable (sid)

gdk-pixbuf

0.17.0-2woody3

0.22.0-8.1

0.22.0-11

gtk+2.0

2.0.2-5woody3

2.6.4-3.1

2.6.10-2

We recommend that you upgrade your gtk+2.0 packages.");

  script_tag(name:"affected", value:"'gtk+2.0' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);