# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844441");
  script_cve_id("CVE-2019-15034", "CVE-2019-20382", "CVE-2020-10702", "CVE-2020-11869", "CVE-2020-1983");
  script_tag(name:"creation_date", value:"2020-05-22 03:00:16 +0000 (Fri, 22 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-26 14:15:00 +0000 (Sun, 26 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-4372-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4372-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4372-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-4372-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that QEMU incorrectly handled bochs-display devices. A
local attacker in a guest could use this to cause a denial of service or
possibly execute arbitrary code in the host. This issue only affected
Ubuntu 19.10. (CVE-2019-15034)

It was discovered that QEMU incorrectly handled memory during certain VNC
operations. A remote attacker could possibly use this issue to cause QEMU
to consume resources, resulting in a denial of service. This issue only
affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 19.10.
(CVE-2019-20382)

It was discovered that QEMU incorrectly generated QEMU Pointer
Authentication signatures on ARM. A local attacker could possibly use this
issue to bypass PAuth. This issue only affected Ubuntu 19.10.
(CVE-2020-10702)

Ziming Zhang discovered that QEMU incorrectly handled ATI VGA emulation. A
local attacker in a guest could use this issue to cause QEMU to crash,
resulting in a denial of service. This issue only affected Ubuntu 20.04
LTS. (CVE-2020-11869)

Aviv Sasson discovered that QEMU incorrectly handled Slirp networking. A
remote attacker could use this issue to cause QEMU to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 19.10.
(CVE-2020-1983)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
