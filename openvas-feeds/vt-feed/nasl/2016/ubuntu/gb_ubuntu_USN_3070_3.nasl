# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842877");
  script_cve_id("CVE-2016-1237", "CVE-2016-5244", "CVE-2016-5400", "CVE-2016-5696", "CVE-2016-5728", "CVE-2016-5828", "CVE-2016-5829", "CVE-2016-6197");
  script_tag(name:"creation_date", value:"2016-09-07 04:38:48 +0000 (Wed, 07 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-3070-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3070-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3070-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-snapdragon' package(s) announced via the USN-3070-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A missing permission check when settings ACLs was discovered in nfsd. A
local user could exploit this flaw to gain access to any file by setting an
ACL. (CVE-2016-1237)

Kangjie Lu discovered an information leak in the Reliable Datagram Sockets
(RDS) implementation in the Linux kernel. A local attacker could use this
to obtain potentially sensitive information from kernel memory.
(CVE-2016-5244)

James Patrick-Evans discovered that the airspy USB device driver in the
Linux kernel did not properly handle certain error conditions. An attacker
with physical access could use this to cause a denial of service (memory
consumption). (CVE-2016-5400)

Yue Cao et al discovered a flaw in the TCP implementation's handling of
challenge acks in the Linux kernel. A remote attacker could use this to
cause a denial of service (reset connection) or inject content into an TCP
stream. (CVE-2016-5696)

Pengfei Wang discovered a race condition in the MIC VOP driver in the Linux
kernel. A local attacker could use this to cause a denial of service
(system crash) or obtain potentially sensitive information from kernel
memory. (CVE-2016-5728)

Cyril Bur discovered that on PowerPC platforms, the Linux kernel mishandled
transactional memory state on exec(). A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2016-5828)

It was discovered that a heap based buffer overflow existed in the USB HID
driver in the Linux kernel. A local attacker could use this cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2016-5829)

It was discovered that the OverlayFS implementation in the Linux kernel did
not properly verify dentry state before proceeding with unlink and rename
operations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2016-6197)");

  script_tag(name:"affected", value:"'linux-snapdragon' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
