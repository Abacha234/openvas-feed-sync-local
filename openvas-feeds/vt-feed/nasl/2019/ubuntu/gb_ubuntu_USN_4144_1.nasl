# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844191");
  script_cve_id("CVE-2018-20976", "CVE-2019-15538");
  script_tag(name:"creation_date", value:"2019-10-02 02:00:39 +0000 (Wed, 02 Oct 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 15:22:00 +0000 (Wed, 02 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4144-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4144-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4144-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4144-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the XFS file system in the Linux kernel did not
properly handle mount failures in some situations. A local attacker could
possibly use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2018-20976)

Benjamin Moody discovered that the XFS file system in the Linux kernel did
not properly handle an error condition when out of disk quota. A local
attacker could possibly use this to cause a denial of service.
(CVE-2019-15538)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-aws-hwe, linux-meta-azure, linux-meta-hwe, linux-meta-kvm, linux-meta-oem, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oem, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure, linux-signed-hwe, linux-signed-oem, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
