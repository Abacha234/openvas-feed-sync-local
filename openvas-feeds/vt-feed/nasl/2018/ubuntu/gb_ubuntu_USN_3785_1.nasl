# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843653");
  script_cve_id("CVE-2017-13144", "CVE-2018-14434", "CVE-2018-14435", "CVE-2018-14436", "CVE-2018-14437", "CVE-2018-14551", "CVE-2018-16323", "CVE-2018-16640", "CVE-2018-16642", "CVE-2018-16643", "CVE-2018-16644", "CVE-2018-16645", "CVE-2018-16749", "CVE-2018-16750");
  script_tag(name:"creation_date", value:"2018-10-05 06:17:46 +0000 (Fri, 05 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3785-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3785-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1793485");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the USN-3785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to a large number of issues discovered in GhostScript that prevent
it from being used by ImageMagick safely, this update includes a
default policy change that disables support for the Postscript and
PDF formats in ImageMagick. This policy can be overridden if necessary
by using an alternate ImageMagick policy configuration.

It was discovered that several memory leaks existed when handling
certain images in ImageMagick. An attacker could use this to cause a
denial of service. (CVE-2018-14434, CVE-2018-14435, CVE-2018-14436,
CVE-2018-14437, CVE-2018-16640, CVE-2018-16750)

It was discovered that ImageMagick did not properly initialize a
variable before using it when processing MAT images. An attacker could
use this to cause a denial of service or possibly execute arbitrary
code. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-14551)

It was discovered that an information disclosure vulnerability existed
in ImageMagick when processing XBM images. An attacker could use this
to expose sensitive information. (CVE-2018-16323)

It was discovered that an out-of-bounds write vulnerability existed
in ImageMagick when handling certain images. An attacker could use
this to cause a denial of service or possibly execute arbitrary code.
(CVE-2018-16642)

It was discovered that ImageMagick did not properly check for errors
in some situations. An attacker could use this to cause a denial of
service. (CVE-2018-16643)

It was discovered that ImageMagick did not properly validate image
meta data in some situations. An attacker could use this to cause a
denial of service. (CVE-2018-16644)

It was discovered that ImageMagick did not prevent excessive memory
allocation when handling certain image types. An attacker could use
this to cause a denial of service. (CVE-2018-16645)

Sergej Schumilo and Cornelius Aschermann discovered that ImageMagick
did not properly check for NULL in some situations when processing
PNG images. An attacker could use this to cause a denial of service.
(CVE-2018-16749)

USN-3681-1 fixed vulnerabilities in Imagemagick. Unfortunately,
the fix for CVE-2017-13144 introduced a regression in ImageMagick in
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. This update reverts the fix
for CVE-2017-13144 for those releases.

We apologize for the inconvenience.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
