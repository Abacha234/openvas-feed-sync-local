# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843632");
  script_cve_id("CVE-2017-13695", "CVE-2018-1118");
  script_tag(name:"creation_date", value:"2018-09-11 05:08:12 +0000 (Tue, 11 Sep 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3762-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3762-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3762-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-raspi2, linux-raspi2' package(s) announced via the USN-3762-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the VirtIO subsystem in the Linux kernel did not
properly initialize memory in some situations. A local attacker could use
this to possibly expose sensitive information (kernel memory).
(CVE-2018-1118)

Seunghun Han discovered an information leak in the ACPI handling code in
the Linux kernel when handling early termination of ACPI table loading. A
local attacker could use this to expose sensitive informal (kernel address
locations). (CVE-2017-13695)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-azure, linux-gcp, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure, linux-meta-gcp, linux-meta-kvm, linux-meta-raspi2, linux-raspi2' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
