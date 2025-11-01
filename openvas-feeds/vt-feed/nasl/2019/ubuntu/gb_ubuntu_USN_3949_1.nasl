# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843979");
  script_cve_id("CVE-2019-2422");
  script_tag(name:"creation_date", value:"2019-04-17 02:00:58 +0000 (Wed, 17 Apr 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-3949-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3949-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3949-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-lts' package(s) announced via the USN-3949-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a memory disclosure issue existed in the OpenJDK
Library subsystem. An attacker could use this to expose sensitive
information and possibly bypass Java sandbox restrictions. (CVE-2019-2422)

Please note that with this update, the OpenJDK package in Ubuntu
18.04 LTS has transitioned from OpenJDK 10 to OpenJDK 11. Several
additional packages were updated to be compatible with OpenJDK 11.");

  script_tag(name:"affected", value:"'openjdk-lts' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
