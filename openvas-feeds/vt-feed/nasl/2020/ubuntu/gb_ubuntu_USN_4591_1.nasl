# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844663");
  script_cve_id("CVE-2020-12351", "CVE-2020-12352");
  script_tag(name:"creation_date", value:"2020-10-21 03:00:28 +0000 (Wed, 21 Oct 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-08 16:15:00 +0000 (Thu, 08 Apr 2021)");

  script_name("Ubuntu: Security Advisory (USN-4591-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4591-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4591-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-hwe, linux-hwe-5.4, linux-meta, linux-meta-hwe, linux-meta-hwe-5.4, linux-meta-oem, linux-meta-raspi, linux-meta-raspi-5.4, linux-meta-snapdragon, linux-oem, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-hwe, linux-signed-hwe-5.4, linux-signed-oem, linux-snapdragon' package(s) announced via the USN-4591-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andy Nguyen discovered that the Bluetooth L2CAP implementation in the Linux
kernel contained a type-confusion error. A physically proximate remote
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2020-12351)

Andy Nguyen discovered that the Bluetooth A2MP implementation in the Linux
kernel did not properly initialize memory in some situations. A physically
proximate remote attacker could use this to expose sensitive information
(kernel memory). (CVE-2020-12352)");

  script_tag(name:"affected", value:"'linux, linux-hwe, linux-hwe-5.4, linux-meta, linux-meta-hwe, linux-meta-hwe-5.4, linux-meta-oem, linux-meta-raspi, linux-meta-raspi-5.4, linux-meta-snapdragon, linux-oem, linux-raspi, linux-raspi-5.4, linux-signed, linux-signed-hwe, linux-signed-hwe-5.4, linux-signed-oem, linux-snapdragon' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
