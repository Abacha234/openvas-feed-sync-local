# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845308");
  script_cve_id("CVE-2022-27666");
  script_tag(name:"creation_date", value:"2022-04-02 01:00:25 +0000 (Sat, 02 Apr 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-29 19:23:00 +0000 (Tue, 29 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5357-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5357-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5357-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws-hwe, linux-azure, linux-gcp, linux-gcp-4.15, linux-meta-gcp-4.15, linux-meta-oracle, linux-meta-raspi2, linux-oracle, linux-raspi2, linux-signed-gcp-4.15, linux-signed-oracle' package(s) announced via the USN-5357-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the IPsec implementation in the Linux kernel did not
properly allocate enough memory when performing ESP transformations,
leading to a heap-based buffer overflow. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code.");

  script_tag(name:"affected", value:"'linux-aws-hwe, linux-azure, linux-gcp, linux-gcp-4.15, linux-meta-gcp-4.15, linux-meta-oracle, linux-meta-raspi2, linux-oracle, linux-raspi2, linux-signed-gcp-4.15, linux-signed-oracle' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
