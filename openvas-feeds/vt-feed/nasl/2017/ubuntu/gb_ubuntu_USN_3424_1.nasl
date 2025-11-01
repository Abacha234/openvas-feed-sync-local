# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843311");
  script_cve_id("CVE-2017-0663", "CVE-2017-7375", "CVE-2017-7376", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050");
  script_tag(name:"creation_date", value:"2017-09-19 05:42:23 +0000 (Tue, 19 Sep 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-17 15:15:00 +0000 (Fri, 17 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-3424-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3424-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3424-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-3424-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a type confusion error existed in libxml2. An
attacker could use this to specially construct XML data that
could cause a denial of service or possibly execute arbitrary
code. (CVE-2017-0663)

It was discovered that libxml2 did not properly validate parsed entity
references. An attacker could use this to specially construct XML
data that could expose sensitive information. (CVE-2017-7375)

It was discovered that a buffer overflow existed in libxml2 when
handling HTTP redirects. An attacker could use this to specially
construct XML data that could cause a denial of service or possibly
execute arbitrary code. (CVE-2017-7376)

Marcel Bohme and Van-Thuan Pham discovered a buffer overflow in
libxml2 when handling elements. An attacker could use this to specially
construct XML data that could cause a denial of service or possibly
execute arbitrary code. (CVE-2017-9047)

Marcel Bohme and Van-Thuan Pham discovered a buffer overread
in libxml2 when handling elements. An attacker could use this
to specially construct XML data that could cause a denial of
service. (CVE-2017-9048)

Marcel Bohme and Van-Thuan Pham discovered multiple buffer overreads
in libxml2 when handling parameter-entity references. An attacker
could use these to specially construct XML data that could cause a
denial of service. (CVE-2017-9049, CVE-2017-9050)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
