# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842778");
  script_cve_id("CVE-2014-2497", "CVE-2014-9709", "CVE-2015-8874", "CVE-2015-8877", "CVE-2016-3074");
  script_tag(name:"creation_date", value:"2016-06-01 03:24:20 +0000 (Wed, 01 Jun 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:57:00 +0000 (Wed, 20 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-2987-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2987-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2987-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgd2' package(s) announced via the USN-2987-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the GD library incorrectly handled certain color
tables in XPM images. If a user or automated system were tricked into
processing a specially crafted XPM image, an attacker could cause a denial
of service. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-2497)

It was discovered that the GD library incorrectly handled certain malformed
GIF images. If a user or automated system were tricked into processing a
specially crafted GIF image, an attacker could cause a denial of service.
This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-9709)

It was discovered that the GD library incorrectly handled memory when using
gdImageFillToBorder(). A remote attacker could possibly use this issue to
cause a denial of service. (CVE-2015-8874)

It was discovered that the GD library incorrectly handled memory when using
gdImageScaleTwoPass(). A remote attacker could possibly use this issue to
cause a denial of service. This issue only applied to Ubuntu 14.04 LTS,
Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2015-8877)

Hans Jerry Illikainen discovered that the GD library incorrectly handled
certain malformed GD images. If a user or automated system were tricked
into processing a specially crafted GD image, an attacker could cause a
denial of service or possibly execute arbitrary code. (CVE-2016-3074)");

  script_tag(name:"affected", value:"'libgd2' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
