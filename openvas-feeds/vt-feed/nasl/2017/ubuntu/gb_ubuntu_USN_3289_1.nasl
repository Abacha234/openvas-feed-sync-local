# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843172");
  script_cve_id("CVE-2017-7377", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8309", "CVE-2017-8379");
  script_tag(name:"creation_date", value:"2017-05-17 04:54:41 +0000 (Wed, 17 May 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 17:20:00 +0000 (Thu, 10 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-3289-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3289-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3289-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-3289-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Li Qiang discovered that QEMU incorrectly handled VirtFS directory sharing.
A privileged attacker inside the guest could use this issue to cause QEMU
to crash, resulting in a denial of service. (CVE-2017-7377, CVE-2017-8086)

Jiangxin discovered that QEMU incorrectly handled the Cirrus VGA device. A
privileged attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2017-7718)

Li Qiang and Jiangxin discovered that QEMU incorrectly handled the Cirrus
VGA device when being used with a VNC connection. A privileged attacker
inside the guest could use this issue to cause QEMU to crash, resulting in
a denial of service, or possibly execute arbitrary code on the host. In the
default installation, when QEMU is used with libvirt, attackers would be
isolated by the libvirt AppArmor profile. (CVE-2017-7980)

Jiang Xin discovered that QEMU incorrectly handled the audio subsystem. A
privileged attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2017-8309)

Jiang Xin discovered that QEMU incorrectly handled the input subsystem. A
privileged attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. This issue only affected Ubuntu
16.04 LTS, Ubuntu 16.10 and Ubuntu 17.04. (CVE-2017-8379)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
