# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842443");
  script_cve_id("CVE-2015-1420", "CVE-2015-4001", "CVE-2015-4002", "CVE-2015-4003", "CVE-2015-5706");
  script_tag(name:"creation_date", value:"2015-09-18 08:43:12 +0000 (Fri, 18 Sep 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_name("Ubuntu: Security Advisory (USN-2667-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2667-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2667-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-2667-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition was discovered in the Linux kernel's file_handle size
verification. A local user could exploit this flaw to read potentially
sensitive memory locations. (CVE-2015-1420)

A underflow error was discovered in the Linux kernel's Ozmo Devices USB
over WiFi host controller driver. A remote attacker could exploit this flaw
to cause a denial of service (system crash) or potentially execute
arbitrary code via a specially crafted packet. (CVE-2015-4001)

A bounds check error was discovered in the Linux kernel's Ozmo Devices USB
over WiFi host controller driver. A remote attacker could exploit this flaw
to cause a denial of service (system crash) or potentially execute
arbitrary code via a specially crafted packet. (CVE-2015-4002)

A division by zero error was discovered in the Linux kernel's Ozmo Devices
USB over WiFi host controller driver. A remote attacker could exploit this
flaw to cause a denial of service (system crash). (CVE-2015-4003)

A double free flaw was discovered in the Linux kernel's path lookup. A
local user could cause a denial of service (Oops). (CVE-2015-5706)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
