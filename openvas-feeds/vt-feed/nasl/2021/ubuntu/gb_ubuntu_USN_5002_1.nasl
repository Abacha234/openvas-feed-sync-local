# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844989");
  script_cve_id("CVE-2021-3609");
  script_tag(name:"creation_date", value:"2021-06-24 03:01:08 +0000 (Thu, 24 Jun 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 15:21:00 +0000 (Thu, 10 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5002-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5002-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5002-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gke-5.3, linux-hwe, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-raspi2-5.3, linux-raspi2-5.3, linux-signed-gke-5.3, linux-signed-hwe' package(s) announced via the USN-5002-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Norbert Slusarek discovered a race condition in the CAN BCM networking
protocol of the Linux kernel leading to multiple use-after-free
vulnerabilities. A local attacker could use this issue to execute arbitrary
code.");

  script_tag(name:"affected", value:"'linux-gke-5.3, linux-hwe, linux-meta-gke-5.3, linux-meta-hwe, linux-meta-raspi2-5.3, linux-raspi2-5.3, linux-signed-gke-5.3, linux-signed-hwe' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
