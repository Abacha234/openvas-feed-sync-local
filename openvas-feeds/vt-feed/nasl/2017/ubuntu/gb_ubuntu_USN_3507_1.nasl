# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843399");
  script_cve_id("CVE-2017-1000405", "CVE-2017-12193", "CVE-2017-15299", "CVE-2017-15306", "CVE-2017-15951", "CVE-2017-16535", "CVE-2017-16643", "CVE-2017-16939");
  script_tag(name:"creation_date", value:"2017-12-09 06:39:06 +0000 (Sat, 09 Dec 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3507-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3507-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3507-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta, linux-meta-raspi2, linux-raspi2' package(s) announced via the USN-3507-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mohamed Ghannam discovered that a use-after-free vulnerability existed in
the Netlink subsystem (XFRM) in the Linux kernel. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-16939)

It was discovered that the Linux kernel did not properly handle copy-on-
write of transparent huge pages. A local attacker could use this to cause a
denial of service (application crashes) or possibly gain administrative
privileges. (CVE-2017-1000405)

Fan Wu, Haoran Qiu, and Shixiong Zhao discovered that the associative array
implementation in the Linux kernel sometimes did not properly handle adding
a new entry. A local attacker could use this to cause a denial of service
(system crash). (CVE-2017-12193)

Eric Biggers discovered that the key management subsystem in the Linux
kernel did not properly restrict adding a key that already exists but is
uninstantiated. A local attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code. (CVE-2017-15299)

It was discovered that a null pointer dereference error existed in the
PowerPC KVM implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash). (CVE-2017-15306)

Eric Biggers discovered a race condition in the key management subsystem of
the Linux kernel around keys in a negative state. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-15951)

Andrey Konovalov discovered that the USB subsystem in the Linux kernel did
not properly validate USB BOS metadata. A physically proximate attacker
could use this to cause a denial of service (system crash).
(CVE-2017-16535)

Andrey Konovalov discovered an out-of-bounds read in the GTCO digitizer USB
driver for the Linux kernel. A physically proximate attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-16643)");

  script_tag(name:"affected", value:"'linux, linux-meta, linux-meta-raspi2, linux-raspi2' package(s) on Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
