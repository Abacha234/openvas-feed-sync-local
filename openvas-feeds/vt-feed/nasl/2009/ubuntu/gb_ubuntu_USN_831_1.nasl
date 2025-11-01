# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64891");
  script_cve_id("CVE-2009-1720", "CVE-2009-1721", "CVE-2009-1722");
  script_tag(name:"creation_date", value:"2009-09-15 20:46:32 +0000 (Tue, 15 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-831-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-831-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-831-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the USN-831-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Drew Yao discovered several flaws in the way OpenEXR handled certain
malformed EXR image files. If a user were tricked into opening a crafted
EXR image file, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2009-1720, CVE-2009-1721)

It was discovered that OpenEXR did not properly handle certain malformed
EXR image files. If a user were tricked into opening a crafted EXR image
file, an attacker could cause a denial of service via application crash, or
possibly execute arbitrary code with the privileges of the user invoking
the program. This issue only affected Ubuntu 8.04 LTS. (CVE-2009-1722)");

  script_tag(name:"affected", value:"'openexr' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
