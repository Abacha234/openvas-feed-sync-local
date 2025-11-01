# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843306");
  script_cve_id("CVE-2017-1000251", "CVE-2017-10663", "CVE-2017-12762", "CVE-2017-8831");
  script_tag(name:"creation_date", value:"2017-09-19 05:41:52 +0000 (Tue, 19 Sep 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-06 01:29:00 +0000 (Fri, 06 Apr 2018)");

  script_name("Ubuntu: Security Advisory (USN-3420-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3420-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3420-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gke, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gke, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) announced via the USN-3420-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a buffer overflow existed in the Bluetooth stack of
the Linux kernel when handling L2CAP configuration responses. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2017-1000251)

It was discovered that the Flash-Friendly File System (f2fs) implementation
in the Linux kernel did not properly validate superblock metadata. A local
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-10663)

It was discovered that a buffer overflow existed in the ioctl handling code
in the ISDN subsystem of the Linux kernel. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-12762)

Pengfei Wang discovered that a race condition existed in the NXP SAA7164 TV
Decoder driver for the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-8831)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gke, linux-kvm, linux-meta, linux-meta-aws, linux-meta-gke, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
