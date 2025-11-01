# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845385");
  script_cve_id("CVE-2022-1664");
  script_tag(name:"creation_date", value:"2022-05-27 01:00:29 +0000 (Fri, 27 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-07 18:18:00 +0000 (Tue, 07 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-5446-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5446-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5446-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpkg' package(s) announced via the USN-5446-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Max Justicz discovered that dpkg incorrectly handled unpacking certain
source packages. If a user or an automated system were tricked into
unpacking a specially crafted source package, a remote attacker could
modify files outside the target unpack directory, leading to a denial of
service or potentially gaining access to the system.");

  script_tag(name:"affected", value:"'dpkg' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10, Ubuntu 22.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
