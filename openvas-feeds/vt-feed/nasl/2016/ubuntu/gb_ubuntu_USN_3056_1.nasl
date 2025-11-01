# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842852");
  script_cve_id("CVE-2016-3135", "CVE-2016-4470", "CVE-2016-4794", "CVE-2016-5243");
  script_tag(name:"creation_date", value:"2016-08-11 03:37:23 +0000 (Thu, 11 Aug 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-3056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3056-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3056-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi2' package(s) announced via the USN-3056-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ben Hawkes discovered an integer overflow in the Linux netfilter
implementation. On systems running 32 bit kernels, a local unprivileged
attacker could use this to cause a denial of service (system crash) or
possibly execute arbitrary code with administrative privileges.
(CVE-2016-3135)

It was discovered that the keyring implementation in the Linux kernel did
not ensure a data structure was initialized before referencing it after an
error condition occurred. A local attacker could use this to cause a denial
of service (system crash). (CVE-2016-4470)

Sasha Levin discovered that a use-after-free existed in the percpu
allocator in the Linux kernel. A local attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code with
administrative privileges. (CVE-2016-4794)

Kangjie Lu discovered an information leak in the netlink implementation of
the Linux kernel. A local attacker could use this to obtain sensitive
information from kernel memory. (CVE-2016-5243)");

  script_tag(name:"affected", value:"'linux-raspi2' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
