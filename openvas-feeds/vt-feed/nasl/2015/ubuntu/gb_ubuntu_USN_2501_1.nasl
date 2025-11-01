# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842094");
  script_cve_id("CVE-2014-8142", "CVE-2014-9427", "CVE-2014-9652", "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-1351", "CVE-2015-1352");
  script_tag(name:"creation_date", value:"2015-02-18 04:41:59 +0000 (Wed, 18 Feb 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2501-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2501-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2501-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-2501-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Esser discovered that PHP incorrectly handled unserializing objects.
A remote attacker could use this issue to cause PHP to crash, resulting in
a denial of service, or possibly execute arbitrary code. (CVE-2014-8142,
CVE-2015-0231)

Brian Carpenter discovered that the PHP CGI component incorrectly handled
invalid files. A local attacker could use this issue to obtain sensitive
information, or possibly execute arbitrary code. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2014-9427)

It was discovered that PHP incorrectly handled certain pascal strings in
the fileinfo extension. A remote attacker could possibly use this issue to
cause PHP to crash, resulting in a denial of service. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2014-9652)

Alex Eubanks discovered that PHP incorrectly handled EXIF data in JPEG
images. A remote attacker could use this issue to cause PHP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2015-0232)

It was discovered that the PHP opcache component incorrectly handled
memory. A remote attacker could possibly use this issue to cause PHP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-1351)

It was discovered that the PHP PostgreSQL database extension incorrectly
handled certain pointers. A remote attacker could possibly use this issue
to cause PHP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 14.04 LTS and
Ubuntu 14.10. (CVE-2015-1352)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
