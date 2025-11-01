# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843885");
  script_cve_id("CVE-2018-14625", "CVE-2018-16882", "CVE-2018-19407", "CVE-2018-19854");
  script_tag(name:"creation_date", value:"2019-01-30 03:03:00 +0000 (Wed, 30 Jan 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:36:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3872-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3872-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3872-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-hwe, linux-meta-hwe, linux-signed-hwe' package(s) announced via the USN-3872-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a race condition existed in the vsock address family
implementation of the Linux kernel that could lead to a use-after-free
condition. A local attacker in a guest virtual machine could use this to
expose sensitive information (host machine kernel memory). (CVE-2018-14625)

Cfir Cohen discovered that a use-after-free vulnerability existed in the
KVM implementation of the Linux kernel, when handling interrupts in
environments where nested virtualization is in use (nested KVM
virtualization is not enabled by default in Ubuntu kernels). A local
attacker in a guest VM could possibly use this to gain administrative
privileges in a host machine. (CVE-2018-16882)

Wei Wu discovered that the KVM implementation in the Linux kernel did not
properly ensure that ioapics were initialized. A local attacker could use
this to cause a denial of service (system crash). (CVE-2018-19407)

It was discovered that the crypto subsystem of the Linux kernel leaked
uninitialized memory to user space in some situations. A local attacker
could use this to expose sensitive information (kernel memory).
(CVE-2018-19854)");

  script_tag(name:"affected", value:"'linux-hwe, linux-meta-hwe, linux-signed-hwe' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
