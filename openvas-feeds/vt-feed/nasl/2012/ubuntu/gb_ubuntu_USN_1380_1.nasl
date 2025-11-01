# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840913");
  script_cve_id("CVE-2011-2518", "CVE-2011-4097", "CVE-2012-0207");
  script_tag(name:"creation_date", value:"2012-03-07 05:49:20 +0000 (Wed, 07 Mar 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-30 19:39:00 +0000 (Thu, 30 Jul 2020)");

  script_name("Ubuntu: Security Advisory (USN-1380-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1380-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1380-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1380-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was discovered in the TOMOYO LSM's handling of mount system calls.
An unprivileged user could oops the system causing a denial of service.
(CVE-2011-2518)

A bug was discovered in the Linux kernel's calculation of OOM (Out of
memory) scores, that would result in the wrong process being killed. A user
could use this to kill the process with the highest OOM score, even if that
process belongs to another user or the system. (CVE-2011-4097)

A flaw was found in the linux kernels IPv4 IGMP query processing. A remote
attacker could exploit this to cause a denial of service. (CVE-2012-0207)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
