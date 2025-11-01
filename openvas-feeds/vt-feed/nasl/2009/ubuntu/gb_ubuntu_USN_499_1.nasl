# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840092");
  script_cve_id("CVE-2006-5752", "CVE-2007-1863", "CVE-2007-3304");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-499-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-499-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-499-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the USN-499-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stefan Esser discovered that mod_status did not force a character set,
which could result in browsers becoming vulnerable to XSS attacks when
processing the output. If a user were tricked into viewing server
status output during a crafted server request, a remote attacker could
exploit this to modify the contents, or steal confidential data (such as
passwords), within the same domain. By default, mod_status is disabled
in Ubuntu. (CVE-2006-5752)

Niklas Edmundsson discovered that the mod_cache module could be made to
crash using a specially crafted request. A remote user could use this
to cause a denial of service if Apache was configured to use a threaded
worker. By default, mod_cache is disabled in Ubuntu. (CVE-2007-1863)

A flaw was discovered in the signal handling of Apache. A local
attacker could trick Apache into sending SIGUSR1 to other processes.
The vulnerable code was only present in Ubuntu Feisty. (CVE-2007-3304)");

  script_tag(name:"affected", value:"'apache2' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
