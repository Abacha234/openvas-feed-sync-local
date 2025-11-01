# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843524");
  script_cve_id("CVE-2017-16845", "CVE-2018-7550", "CVE-2018-7858");
  script_tag(name:"creation_date", value:"2018-05-17 03:36:39 +0000 (Thu, 17 May 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 17:42:00 +0000 (Thu, 10 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-3649-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3649-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3649-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-3649-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cyrille Chatras discovered that QEMU incorrectly handled certain PS2 values
during migration. An attacker could possibly use this issue to cause QEMU
to crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 18.04 LTS. (CVE-2017-16845)

Cyrille Chatras discovered that QEMU incorrectly handled multiboot. An
attacker could use this issue to cause QEMU to crash, resulting in a denial
of service, or possibly execute arbitrary code on the host. In the default
installation, when QEMU is used with libvirt, attackers would be isolated
by the libvirt AppArmor profile. (CVE-2018-7550)

Ross Lagerwall discovered that QEMU incorrectly handled the Cirrus VGA
device. A privileged attacker inside the guest could use this issue to
cause QEMU to crash, resulting in a denial of service. This issue only
affected Ubuntu 17.10 and Ubuntu 18.04 LTS. (CVE-2018-7858)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
