# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840446");
  script_cve_id("CVE-2010-1411", "CVE-2010-2065", "CVE-2010-2067");
  script_tag(name:"creation_date", value:"2010-06-25 10:25:26 +0000 (Fri, 25 Jun 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-954-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-954-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-954-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the USN-954-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kevin Finisterre discovered that the TIFF library did not correctly handle
certain image structures. If a user or automated system were tricked
into opening a specially crafted TIFF image, a remote attacker could
execute arbitrary code with user privileges, or crash the application,
leading to a denial of service. (CVE-2010-1411)

Dan Rosenberg and Sauli Pahlman discovered multiple flaws in the TIFF
library. If a user or automated system were into opening a specially
crafted TIFF image, a remote attacker could execute arbitrary code
with user privileges, or crash the application, leading to a denial
of service. (Only Ubuntu 10.04 LTS was affected.) (CVE-2010-2065,
CVE-2010-2067)");

  script_tag(name:"affected", value:"'tiff' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
