# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841820");
  script_cve_id("CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");
  script_tag(name:"creation_date", value:"2014-05-12 03:43:38 +0000 (Mon, 12 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2205-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2205-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2205-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the USN-2205-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pedro Ribeiro discovered that LibTIFF incorrectly handled certain
malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. This issue only
affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4231)

Pedro Ribeiro discovered that LibTIFF incorrectly handled certain
malformed images when using the tiff2pdf tool. If a user or automated
system were tricked into opening a specially crafted TIFF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. This issue only
affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4232)

Murray McAllister discovered that LibTIFF incorrectly handled certain
malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. (CVE-2013-4243)

Huzaifa Sidhpurwala discovered that LibTIFF incorrectly handled certain
malformed images when using the gif2tiff tool. If a user or automated
system were tricked into opening a specially crafted GIF image, a remote
attacker could crash the application, leading to a denial of service, or
possibly execute arbitrary code with user privileges. This issue only
affected Ubuntu 10.04 LTS, Ubunu 12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10.
(CVE-2013-4244)");

  script_tag(name:"affected", value:"'tiff' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
