# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844407");
  script_cve_id("CVE-2020-11884");
  script_tag(name:"creation_date", value:"2020-04-29 03:01:03 +0000 (Wed, 29 Apr 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-04 22:15:00 +0000 (Mon, 04 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-4343-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4343-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4343-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta, linux-signed' package(s) announced via the USN-4343-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Al Viro discovered that the Linux kernel for s390x systems did not properly
perform page table upgrades for kernel sections that use secondary address
mode. A local attacker could use this to cause a denial of service (system
crash) or execute arbitrary code.");

  script_tag(name:"affected", value:"'linux, linux-meta, linux-signed' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
