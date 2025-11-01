# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844390");
  script_cve_id("CVE-2018-12641", "CVE-2018-12697", "CVE-2018-12698", "CVE-2018-12934", "CVE-2018-17794", "CVE-2018-17985", "CVE-2018-18483", "CVE-2018-18484", "CVE-2018-18700", "CVE-2018-18701", "CVE-2018-9138", "CVE-2019-14250", "CVE-2019-9070", "CVE-2019-9071");
  script_tag(name:"creation_date", value:"2020-04-09 03:00:29 +0000 (Thu, 09 Apr 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-10 19:22:00 +0000 (Fri, 10 Dec 2021)");

  script_name("Ubuntu: Security Advisory (USN-4326-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4326-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4326-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libiberty' package(s) announced via the USN-4326-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libiberty incorrectly handled parsing certain
binaries. If a user or automated system were tricked into processing a
specially crafted binary, a remote attacker could use this issue to cause
libiberty to crash, resulting in a denial of service, or possibly execute
arbitrary code");

  script_tag(name:"affected", value:"'libiberty' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
