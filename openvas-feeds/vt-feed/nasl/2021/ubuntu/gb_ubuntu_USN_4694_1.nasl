# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844786");
  script_cve_id("CVE-2020-28374");
  script_tag(name:"creation_date", value:"2021-01-15 04:00:14 +0000 (Fri, 15 Jan 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-15 22:04:00 +0000 (Mon, 15 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-4694-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4694-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4694-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-hwe, linux-hwe-5.4, linux-hwe-5.8, linux-lts-xenial, linux-meta, linux-meta-hwe, linux-meta-hwe-5.4, linux-meta-hwe-5.8, linux-signed, linux-signed-hwe, linux-signed-hwe-5.4, linux-signed-hwe-5.8' package(s) announced via the USN-4694-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the LIO SCSI target implementation in the Linux
kernel performed insufficient identifier checking in certain XCOPY
requests. An attacker with access to at least one LUN in a multiple
backstore environment could use this to expose sensitive information or
modify data.");

  script_tag(name:"affected", value:"'linux, linux-hwe, linux-hwe-5.4, linux-hwe-5.8, linux-lts-xenial, linux-meta, linux-meta-hwe, linux-meta-hwe-5.4, linux-meta-hwe-5.8, linux-signed, linux-signed-hwe, linux-signed-hwe-5.4, linux-signed-hwe-5.8' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
