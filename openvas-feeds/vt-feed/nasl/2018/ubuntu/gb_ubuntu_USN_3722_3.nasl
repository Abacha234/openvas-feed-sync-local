# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843601");
  script_cve_id("CVE-2018-0360", "CVE-2018-0361");
  script_tag(name:"creation_date", value:"2018-07-27 04:00:32 +0000 (Fri, 27 Jul 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3722-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3722-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3722-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1783632");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the USN-3722-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3722-1 fixed vulnerabilities in ClamAV. The updated ClamAV version
removed some configuration options which caused the daemon to fail to start
in environments where the ClamAV configuration file was manually edited.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that ClamAV incorrectly handled parsing certain HWP
 files. A remote attacker could use this issue to cause ClamAV to hang,
 resulting in a denial of service. (CVE-2018-0360)

 It was discovered that ClamAV incorrectly handled parsing certain PDF
 files. A remote attacker could use this issue to cause ClamAV to hang,
 resulting in a denial of service. (CVE-2018-0361)");

  script_tag(name:"affected", value:"'clamav' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
