# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841577");
  script_cve_id("CVE-2013-1819", "CVE-2013-2237", "CVE-2013-4254");
  script_tag(name:"creation_date", value:"2013-10-03 04:50:48 +0000 (Thu, 03 Oct 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1972-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1972-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1972-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1972-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vince Weaver discovered a flaw in the perf subsystem of the Linux kernel on
ARM platforms. A local user could exploit this flaw to gain privileges or
cause a denial of service (system crash). (CVE-2013-4254)

A failure to validate block numbers was discovered in the Linux kernel's
implementation of the XFS filesystem. A local user can cause a denial of
service (system crash) if they can mount, or cause to be mounted a
corrupted or special crafted XFS filesystem. (CVE-2013-1819)

An information leak was discovered in the Linux kernel when reading
broadcast messages from the notify_policy interface of the IPSec
key_socket. A local user could exploit this flaw to examine potentially
sensitive information in kernel memory.
(CVE-2013-2237)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
