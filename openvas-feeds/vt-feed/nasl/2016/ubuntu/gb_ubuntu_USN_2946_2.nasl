# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842709");
  script_cve_id("CVE-2015-8812", "CVE-2016-2085", "CVE-2016-2550", "CVE-2016-2847");
  script_tag(name:"creation_date", value:"2016-04-07 03:01:06 +0000 (Thu, 07 Apr 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-2946-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2946-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2946-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-2946-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Venkatesh Pottem discovered a use-after-free vulnerability in the Linux
kernel's CXGB3 driver. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2015-8812)

Xiaofei Rex Guo discovered a timing side channel vulnerability in the Linux
Extended Verification Module (EVM). An attacker could use this to affect
system integrity. (CVE-2016-2085)

David Herrmann discovered that the Linux kernel incorrectly accounted file
descriptors to the original opener for in-flight file descriptors sent over
a unix domain socket. A local attacker could use this to cause a denial of
service (resource exhaustion). (CVE-2016-2550)

It was discovered that the Linux kernel did not enforce limits on the
amount of data allocated to buffer pipes. A local attacker could use this
to cause a denial of service (resource exhaustion). (CVE-2016-2847)");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
