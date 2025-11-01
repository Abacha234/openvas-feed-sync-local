# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841027");
  script_cve_id("CVE-2011-4409");
  script_tag(name:"creation_date", value:"2012-06-08 04:43:54 +0000 (Fri, 08 Jun 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1465-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1465-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1465-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ubuntuone-client' package(s) announced via the USN-1465-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1465-1 fixed vulnerabilities in Ubuntu One Client. The update failed to
install on certain Ubuntu 10.04 LTS systems that had a legacy Python 2.5
package installed. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the Ubuntu One Client incorrectly validated server
 certificates when using HTTPS connections. If a remote attacker were able
 to perform a machine-in-the-middle attack, this flaw could be exploited to
 alter or compromise confidential information.");

  script_tag(name:"affected", value:"'ubuntuone-client' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
