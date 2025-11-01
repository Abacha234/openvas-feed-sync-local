# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843944");
  script_cve_id("CVE-2018-16867", "CVE-2018-16872", "CVE-2018-19489", "CVE-2018-20123", "CVE-2018-20124", "CVE-2018-20125", "CVE-2018-20126", "CVE-2018-20191", "CVE-2018-20216", "CVE-2019-3812", "CVE-2019-6778");
  script_tag(name:"creation_date", value:"2019-03-28 13:46:13 +0000 (Thu, 28 Mar 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3923-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3923-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-3923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michael Hanselmann discovered that QEMU incorrectly handled the Media
Transfer Protocol (MTP). An attacker inside the guest could use this issue
to read or write arbitrary files and cause a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 18.10.
(CVE-2018-16867)

Michael Hanselmann discovered that QEMU incorrectly handled the Media
Transfer Protocol (MTP). An attacker inside the guest could use this issue
to read arbitrary files, contrary to expectations. This issue only affected
Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-16872)

Zhibin Hu discovered that QEMU incorrectly handled the Plan 9 File System
support. An attacker inside the guest could use this issue to cause QEMU to
crash, resulting in a denial of service. (CVE-2018-19489)

Li Quang and Saar Amar discovered multiple issues in the QEMU PVRDMA
device. An attacker inside the guest could use these issues to cause a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 18.10. These issues were resolved by disabling PVRDMA
support in Ubuntu 18.10. (CVE-2018-20123, CVE-2018-20124, CVE-2018-20125,
CVE-2018-20126, CVE-2018-20191, CVE-2018-20216)

Michael Hanselmann discovered that QEMU incorrectly handled certain i2c
commands. A local attacker could possibly use this issue to read QEMU
process memory. This issue only affected Ubuntu 18.04 LTS and Ubuntu 18.10.
(CVE-2019-3812)

It was discovered that QEMU incorrectly handled the Slirp networking
back-end. An attacker inside the guest could use this issue to cause QEMU
to crash, resulting in a denial of service, or possibly execute arbitrary
code on the host. In the default installation, when QEMU is used with
libvirt, attackers would be isolated by the libvirt AppArmor profile.
(CVE-2019-6778)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
