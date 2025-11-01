# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844066");
  script_cve_id("CVE-2019-12817");
  script_tag(name:"creation_date", value:"2019-06-25 02:00:45 +0000 (Tue, 25 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 17:17:00 +0000 (Mon, 18 Apr 2022)");

  script_name("Ubuntu: Security Advisory (USN-4031-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4031-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4031-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-hwe, linux-meta, linux-meta-hwe, linux-signed, linux-signed-hwe' package(s) announced via the USN-4031-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Linux kernel did not properly separate certain
memory mappings when creating new userspace processes on 64-bit Power
(ppc64el) systems. A local attacker could use this to access memory
contents or cause memory corruption of other processes on the system.");

  script_tag(name:"affected", value:"'linux, linux-hwe, linux-meta, linux-meta-hwe, linux-signed, linux-signed-hwe' package(s) on Ubuntu 18.04, Ubuntu 18.10, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
