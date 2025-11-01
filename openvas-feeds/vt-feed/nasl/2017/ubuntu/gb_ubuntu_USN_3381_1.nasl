# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843273");
  script_cve_id("CVE-2016-8405", "CVE-2017-1000365", "CVE-2017-2618", "CVE-2017-7482");
  script_tag(name:"creation_date", value:"2017-08-08 05:20:22 +0000 (Tue, 08 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3381-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3381-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3381-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta' package(s) announced via the USN-3381-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter Pi discovered that the colormap handling for frame buffer devices in
the Linux kernel contained an integer overflow. A local attacker could use
this to disclose sensitive information (kernel memory). (CVE-2016-8405)

It was discovered that the Linux kernel did not properly restrict
RLIMIT_STACK size. A local attacker could use this in conjunction with
another vulnerability to possibly execute arbitrary code.
(CVE-2017-1000365)

It was discovered that SELinux in the Linux kernel did not properly handle
empty writes to /proc/pid/attr. A local attacker could use this to cause a
denial of service (system crash). (CVE-2017-2618)

Shi Lei discovered that the RxRPC Kerberos 5 ticket handling code in the
Linux kernel did not properly verify metadata. A remote attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-7482)");

  script_tag(name:"affected", value:"'linux, linux-meta' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
