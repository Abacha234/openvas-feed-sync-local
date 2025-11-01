# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842051");
  script_cve_id("CVE-2014-9447");
  script_tag(name:"creation_date", value:"2015-01-23 11:58:11 +0000 (Fri, 23 Jan 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2482-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2482-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2482-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils' package(s) announced via the USN-2482-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Cherepanov discovered that libelf1 incorrectly handled certain
filesystem paths while extracting ar archives. An attacker could use this flaw
to perform a directory traversal attack on the root directory if the process
extracting the ar archive has write access to the root directory.");

  script_tag(name:"affected", value:"'elfutils' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
