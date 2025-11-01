# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843286");
  script_cve_id("CVE-2017-1000365", "CVE-2017-10810", "CVE-2017-7482", "CVE-2017-7533");
  script_tag(name:"creation_date", value:"2017-08-17 05:52:25 +0000 (Thu, 17 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3392-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3392-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3392-2");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/bugs/1709032");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3378-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-xenial, linux-meta-lts-xenial' package(s) announced via the USN-3392-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3392-1 fixed a regression in the Linux kernel for Ubuntu 16.04 LTS.
This update provides the corresponding updates for the Linux Hardware
Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu 14.04 LTS.

USN-3378-2 fixed vulnerabilities in the Linux Hardware Enablement
kernel. Unfortunately, a regression was introduced that prevented
conntrack from working correctly in some situations. This update
fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Fan Wu and Shixiong Zhao discovered a race condition between inotify events
 and vfs rename operations in the Linux kernel. An unprivileged local
 attacker could use this to cause a denial of service (system crash) or
 execute arbitrary code. (CVE-2017-7533)

 It was discovered that the Linux kernel did not properly restrict
 RLIMIT_STACK size. A local attacker could use this in conjunction with
 another vulnerability to possibly execute arbitrary code.
 (CVE-2017-1000365)

 Li Qiang discovered that the Virtio GPU driver in the Linux kernel did not
 properly free memory in some situations. A local attacker could use this to
 cause a denial of service (memory consumption). (CVE-2017-10810)

 Shi Lei discovered that the RxRPC Kerberos 5 ticket handling code in the
 Linux kernel did not properly verify metadata. A remote attacker could use
 this to cause a denial of service (system crash) or possibly execute
 arbitrary code. (CVE-2017-7482)");

  script_tag(name:"affected", value:"'linux-lts-xenial, linux-meta-lts-xenial' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
