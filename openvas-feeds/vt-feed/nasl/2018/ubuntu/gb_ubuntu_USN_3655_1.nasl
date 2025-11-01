# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843532");
  script_cve_id("CVE-2017-12134", "CVE-2017-13220", "CVE-2017-13305", "CVE-2017-17449", "CVE-2017-18079", "CVE-2017-18203", "CVE-2017-18204", "CVE-2017-18208", "CVE-2017-18221", "CVE-2018-3639", "CVE-2018-8822");
  script_tag(name:"creation_date", value:"2018-05-22 10:42:26 +0000 (Tue, 22 May 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3655-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3655-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3655-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/Variant4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta' package(s) announced via the USN-3655-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn and Ken Johnson discovered that microprocessors utilizing
speculative execution of a memory read may allow unauthorized memory
reads via a sidechannel attack. This flaw is known as Spectre
Variant 4. A local attacker could use this to expose sensitive
information, including kernel memory. (CVE-2018-3639)

Jan H. Schonherr discovered that the Xen subsystem did not properly handle
block IO merges correctly in some situations. An attacker in a guest vm
could use this to cause a denial of service (host crash) or possibly gain
administrative privileges in the host. (CVE-2017-12134)

It was discovered that the Bluetooth HIP Protocol implementation in the
Linux kernel did not properly validate HID connection setup information. An
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2017-13220)

It was discovered that a buffer overread vulnerability existed in the
keyring subsystem of the Linux kernel. A local attacker could possibly use
this to expose sensitive information (kernel memory). (CVE-2017-13305)

It was discovered that the netlink subsystem in the Linux kernel did not
properly restrict observations of netlink messages to the appropriate net
namespace. A local attacker could use this to expose sensitive information
(kernel netlink traffic). (CVE-2017-17449)

It was discovered that a race condition existed in the i8042 serial device
driver implementation in the Linux kernel. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-18079)

It was discovered that a race condition existed in the Device Mapper
component of the Linux kernel. A local attacker could use this to cause a
denial of service (system crash). (CVE-2017-18203)

It was discovered that a race condition existed in the OCFS2 file system
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (kernel deadlock). (CVE-2017-18204)

It was discovered that an infinite loop could occur in the madvise(2)
implementation in the Linux kernel in certain circumstances. A local
attacker could use this to cause a denial of service (system hang).
(CVE-2017-18208)

Kefeng Wang discovered that a race condition existed in the memory locking
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service. (CVE-2017-18221)

Silvio Cesare discovered a buffer overwrite existed in the NCPFS
implementation in the Linux kernel. A remote attacker controlling a
malicious NCPFS server could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-8822)");

  script_tag(name:"affected", value:"'linux, linux-meta' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
