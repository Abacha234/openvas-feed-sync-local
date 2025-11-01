# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843200");
  script_cve_id("CVE-2016-7913", "CVE-2016-7917", "CVE-2016-8632", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9604", "CVE-2017-0605", "CVE-2017-2596", "CVE-2017-2671", "CVE-2017-6001", "CVE-2017-7472", "CVE-2017-7618", "CVE-2017-7645", "CVE-2017-7889", "CVE-2017-7895");
  script_tag(name:"creation_date", value:"2017-06-08 04:04:01 +0000 (Thu, 08 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3312-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3312-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3312-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-gke, linux-meta, linux-meta-aws, linux-meta-gke, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) announced via the USN-3312-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the netfilter netlink implementation in the Linux
kernel did not properly validate batch messages. A local attacker with the
CAP_NET_ADMIN capability could use this to expose sensitive information or
cause a denial of service. (CVE-2016-7917)

Qian Zhang discovered a heap-based buffer overflow in the tipc_msg_build()
function in the Linux kernel. A local attacker could use to cause a denial
of service (system crash) or possibly execute arbitrary code with
administrative privileges. (CVE-2016-8632)

It was discovered that the keyring implementation in the Linux kernel in
some situations did not prevent special internal keyrings from being joined
by userspace keyrings. A privileged local attacker could use this to bypass
module verification. (CVE-2016-9604)

It was discovered that a buffer overflow existed in the trace subsystem in
the Linux kernel. A privileged local attacker could use this to execute
arbitrary code. (CVE-2017-0605)

Dmitry Vyukov discovered that KVM implementation in the Linux kernel
improperly emulated the VMXON instruction. A local attacker in a guest OS
could use this to cause a denial of service (memory consumption) in the
host OS. (CVE-2017-2596)

Daniel Jiang discovered that a race condition existed in the ipv4 ping
socket implementation in the Linux kernel. A local privileged attacker
could use this to cause a denial of service (system crash). (CVE-2017-2671)

Di Shen discovered that a race condition existed in the perf subsystem of
the Linux kernel. A local attacker could use this to cause a denial of
service or possibly gain administrative privileges. (CVE-2017-6001)

Eric Biggers discovered a memory leak in the keyring implementation in the
Linux kernel. A local attacker could use this to cause a denial of service
(memory consumption). (CVE-2017-7472)

Sabrina Dubroca discovered that the asynchronous cryptographic hash (ahash)
implementation in the Linux kernel did not properly handle a full request
queue. A local attacker could use this to cause a denial of service
(infinite recursion). (CVE-2017-7618)

Tuomas Haanpaa and Ari Kauppi discovered that the NFSv2 and NFSv3 server
implementations in the Linux kernel did not properly handle certain long
RPC replies. A remote attacker could use this to cause a denial of service
(system crash). (CVE-2017-7645)

Tommi Rantala and Brad Spengler discovered that the memory manager in the
Linux kernel did not properly enforce the CONFIG_STRICT_DEVMEM protection
mechanism. A local attacker with access to /dev/mem could use this to
expose sensitive information or possibly execute arbitrary code.
(CVE-2017-7889)

Tuomas Haanpaa and Ari Kauppi discovered that the NFSv2 and NFSv3 server
implementations in the Linux kernel did not properly check for the end of
buffer. A remote attacker could use this to craft requests that cause a
denial of service (system crash) or possibly execute ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-gke, linux-meta, linux-meta-aws, linux-meta-gke, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
