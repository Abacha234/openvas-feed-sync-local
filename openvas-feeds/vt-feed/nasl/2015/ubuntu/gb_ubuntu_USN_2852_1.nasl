# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842582");
  script_cve_id("CVE-2015-8709");
  script_tag(name:"creation_date", value:"2015-12-20 04:40:17 +0000 (Sun, 20 Dec 2015)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Ubuntu: Security Advisory (USN-2852-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2852-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2852-1");
  script_xref(name:"URL", value:"http://bugs.launchpad.net/bugs/1527374");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi2' package(s) announced via the USN-2852-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jann Horn discovered a ptrace issue with user namespaces in the Linux
kernel. The namespace owner could potentially exploit this flaw by ptracing
a root owned process entering the user namespace to elevate its privileges
and potentially gain access outside of the namespace.
([link moved to references] CVE-2015-8709)");

  script_tag(name:"affected", value:"'linux-raspi2' package(s) on Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
