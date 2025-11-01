# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842880");
  script_cve_id("CVE-2011-5326", "CVE-2014-9762", "CVE-2014-9763", "CVE-2014-9764", "CVE-2014-9771", "CVE-2016-3993", "CVE-2016-3994", "CVE-2016-4024");
  script_tag(name:"creation_date", value:"2016-09-09 04:02:11 +0000 (Fri, 09 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-3075-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3075-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3075-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imlib2' package(s) announced via the USN-3075-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Wilk discovered an out of bounds read in the GIF loader
implementation in Imlib2. An attacker could use this to cause a
denial of service (application crash) or possibly obtain sensitive
information. (CVE-2016-3994)

Yuriy M. Kaminskiy discovered an off-by-one error when handling
coordinates in Imlib2. An attacker could use this to cause a denial of
service (application crash). (CVE-2016-3993)

Yuriy M. Kaminskiy discovered that integer overflows existed in Imlib2
when handling images with large dimensions. An attacker could use
this to cause a denial of service (memory exhaustion or application
crash). (CVE-2014-9771, CVE-2016-4024)

Kevin Ryde discovered that the ellipse drawing code in Imlib2 would
attempt to divide by zero when drawing a 2x1 ellipse. An attacker
could use this to cause a denial of service (application crash).
(CVE-2011-5326)

It was discovered that Imlib2 did not properly handled GIF images
without colormaps. An attacker could use this to cause a denial of
service (application crash). This issue only affected Ubuntu 12.04 LTS
and Ubuntu 14.04 LTS. (CVE-2014-9762)

It was discovered that Imlib2 did not properly handle some PNM images,
leading to a division by zero. An attacker could use this to cause
a denial of service (application crash). This issue only affected
Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-9763)

It was discovered that Imlib2 did not properly handle error conditions
when loading some GIF images. An attacker could use this to cause
a denial of service (application crash). This issue only affected
Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-9764)");

  script_tag(name:"affected", value:"'imlib2' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
