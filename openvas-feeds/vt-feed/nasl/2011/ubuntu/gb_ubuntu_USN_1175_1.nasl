# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840714");
  script_cve_id("CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2692");
  script_tag(name:"creation_date", value:"2011-08-02 07:08:31 +0000 (Tue, 02 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-06 15:53:00 +0000 (Thu, 06 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-1175-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1175-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1175-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng' package(s) announced via the USN-1175-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Frank Busse discovered that libpng did not properly handle certain
malformed PNG images. If a user or automated system were tricked into
opening a crafted PNG file, an attacker could cause libpng to crash,
resulting in a denial of service. This issue only affected Ubuntu
10.04 LTS, 10.10, and 11.04. (CVE-2011-2501)

It was discovered that libpng did not properly handle certain malformed PNG
images. If a user or automated system were tricked into opening a crafted
PNG file, an attacker could cause a denial of service or possibly execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2011-2690)

Frank Busse discovered that libpng did not properly handle certain PNG
images with invalid sCAL chunks. If a user or automated system were tricked
into opening a crafted PNG file, an attacker could cause a denial of
service or possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2011-2692)");

  script_tag(name:"affected", value:"'libpng' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
