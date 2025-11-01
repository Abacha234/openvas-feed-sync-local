# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845497");
  script_cve_id("CVE-2021-33061", "CVE-2021-33656");
  script_tag(name:"creation_date", value:"2022-08-31 01:00:36 +0000 (Wed, 31 Aug 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 13:44:00 +0000 (Thu, 28 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-5589-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5589-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5589-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta, linux-meta-raspi, linux-raspi, linux-signed' package(s) announced via the USN-5589-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Asaf Modelevsky discovered that the Intel(R) 10GbE PCI Express (ixgbe)
Ethernet driver for the Linux kernel performed insufficient control flow
management. A local attacker could possibly use this to cause a denial of
service. (CVE-2021-33061)

It was discovered that the virtual terminal driver in the Linux kernel did
not properly handle VGA console font changes, leading to an out-of-bounds
write. A local attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2021-33656)");

  script_tag(name:"affected", value:"'linux, linux-meta, linux-meta-raspi, linux-raspi, linux-signed' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
