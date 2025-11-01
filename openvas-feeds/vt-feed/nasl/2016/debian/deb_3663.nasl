# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703663");
  script_cve_id("CVE-2016-7092", "CVE-2016-7094", "CVE-2016-7154");
  script_tag(name:"creation_date", value:"2016-09-08 22:00:00 +0000 (Thu, 08 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Debian: Security Advisory (DSA-3663)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3663");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3663");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-3663 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-7092 (XSA-185) Jeremie Boutoille of Quarkslab and Shangcong Luan of Alibaba discovered a flaw in the handling of L3 pagetable entries, allowing a malicious 32-bit PV guest administrator can escalate their privilege to that of the host.

CVE-2016-7094 (XSA-187) x86 HVM guests running with shadow paging use a subset of the x86 emulator to handle the guest writing to its own pagetables. Andrew Cooper of Citrix discovered that there are situations a guest can provoke which result in exceeding the space allocated for internal state. A malicious HVM guest administrator can cause Xen to fail a bug check, causing a denial of service to the host.

CVE-2016-7154 (XSA-188) Mikhail Gorobets of Advanced Threat Research, Intel Security discovered a use after free flaw in the FIFO event channel code. A malicious guest administrator can crash the host, leading to a denial of service. Arbitrary code execution (and therefore privilege escalation), and information leaks, cannot be excluded.

For the stable distribution (jessie), these problems have been fixed in version 4.4.1-9+deb8u7.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);