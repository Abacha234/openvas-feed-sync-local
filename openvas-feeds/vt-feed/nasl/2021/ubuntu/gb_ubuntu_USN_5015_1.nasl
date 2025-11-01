# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845001");
  script_cve_id("CVE-2021-28691", "CVE-2021-33909", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-3587");
  script_tag(name:"creation_date", value:"2021-07-21 03:00:53 +0000 (Wed, 21 Jul 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-29 17:46:00 +0000 (Thu, 29 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-5015-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5015-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5015-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-oem-5.10, linux-oem-5.10, linux-signed-oem-5.10' package(s) announced via the USN-5015-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the virtual file system implementation in the Linux
kernel contained an unsigned to signed integer conversion error. A local
attacker could use this to cause a denial of service (system crash) or
execute arbitrary code. (CVE-2021-33909)

Michael Brown discovered that the Xen netback driver in the Linux kernel
did not properly handle malformed packets from a network PV frontend,
leading to a use-after-free vulnerability. An attacker in a guest VM could
use this to cause a denial of service or possibly execute arbitrary code.
(CVE-2021-28691)

It was discovered that the bluetooth subsystem in the Linux kernel did not
properly handle HCI device initialization failure, leading to a double-free
vulnerability. An attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2021-3564)

It was discovered that the bluetooth subsystem in the Linux kernel did not
properly handle HCI device detach events, leading to a use-after-free
vulnerability. An attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2021-3573)

It was discovered that the NFC implementation in the Linux kernel did not
properly handle failed connect events leading to a NULL pointer
dereference. A local attacker could use this to cause a denial of service.
(CVE-2021-3587)");

  script_tag(name:"affected", value:"'linux-meta-oem-5.10, linux-oem-5.10, linux-signed-oem-5.10' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
