# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844439");
  script_cve_id("CVE-2019-19769", "CVE-2020-11494", "CVE-2020-11565", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668", "CVE-2020-11669", "CVE-2020-12657");
  script_tag(name:"creation_date", value:"2020-05-20 03:00:27 +0000 (Wed, 20 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-13 09:15:00 +0000 (Sat, 13 Jun 2020)");

  script_name("Ubuntu: Security Advisory (USN-4368-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4368-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4368-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-gke-5.0, linux-meta-gke-5.0, linux-meta-oem-osp1, linux-oem-osp1, linux-signed-gke-5.0, linux-signed-oem-osp1' package(s) announced via the USN-4368-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tristan Madani discovered that the file locking implementation in the Linux
kernel contained a race condition. A local attacker could possibly use this
to cause a denial of service or expose sensitive information.
(CVE-2019-19769)

It was discovered that the Serial CAN interface driver in the Linux kernel
did not properly initialize data. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2020-11494)

It was discovered that the linux kernel did not properly validate certain
mount options to the tmpfs virtual memory file system. A local attacker
with the ability to specify mount options could use this to cause a denial
of service (system crash). (CVE-2020-11565)

It was discovered that the OV51x USB Camera device driver in the Linux
kernel did not properly validate device metadata. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2020-11608)

It was discovered that the STV06XX USB Camera device driver in the Linux
kernel did not properly validate device metadata. A physically proximate
attacker could use this to cause a denial of service (system crash).
(CVE-2020-11609)

It was discovered that the Xirlink C-It USB Camera device driver in the
Linux kernel did not properly validate device metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2020-11668)

David Gibson discovered that the Linux kernel on Power9 CPUs did not
properly save and restore Authority Mask registers state in some
situations. A local attacker in a guest VM could use this to cause a denial
of service (host system crash). (CVE-2020-11669)

It was discovered that the block layer in the Linux kernel contained a race
condition leading to a use-after-free vulnerability. A local attacker could
possibly use this to cause a denial of service (system crash) or execute
arbitrary code. (CVE-2020-12657)");

  script_tag(name:"affected", value:"'linux-gke-5.0, linux-meta-gke-5.0, linux-meta-oem-osp1, linux-oem-osp1, linux-signed-gke-5.0, linux-signed-oem-osp1' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
