# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844382");
  script_cve_id("CVE-2020-8428");
  script_tag(name:"creation_date", value:"2020-04-07 03:00:24 +0000 (Tue, 07 Apr 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-10 20:15:00 +0000 (Wed, 10 Jun 2020)");

  script_name("Ubuntu: Security Advisory (USN-4320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4320-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4320-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) announced via the USN-4320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Al Viro discovered that the vfs layer in the Linux kernel contained a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly expose sensitive information (kernel
memory).");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
