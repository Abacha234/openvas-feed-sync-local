# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844845");
  script_cve_id("CVE-2019-14834", "CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686", "CVE-2020-25687");
  script_tag(name:"creation_date", value:"2021-02-25 04:00:26 +0000 (Thu, 25 Feb 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4698-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4698-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4698-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1916462");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the USN-4698-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4698-1 fixed vulnerabilities in Dnsmasq. The updates introduced
regressions in certain environments related to issues with multiple
queries, and issues with retries. This update fixes the problem.

Original advisory details:

 Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly handled
 memory when sorting RRsets. A remote attacker could use this issue to cause
 Dnsmasq to hang, resulting in a denial of service, or possibly execute
 arbitrary code. (CVE-2020-25681, CVE-2020-25687)

 Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly handled
 extracting certain names. A remote attacker could use this issue to cause
 Dnsmasq to hang, resulting in a denial of service, or possibly execute
 arbitrary code. (CVE-2020-25682, CVE-2020-25683)

 Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly
 implemented address/port checks. A remote attacker could use this issue to
 perform a cache poisoning attack. (CVE-2020-25684)

 Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly
 implemented query resource name checks. A remote attacker could use this
 issue to perform a cache poisoning attack. (CVE-2020-25685)

 Moshe Kol and Shlomi Oberman discovered that Dnsmasq incorrectly handled
 multiple query requests for the same resource name. A remote attacker could
 use this issue to perform a cache poisoning attack. (CVE-2020-25686)

 It was discovered that Dnsmasq incorrectly handled memory during DHCP
 response creation. A remote attacker could possibly use this issue to
 cause Dnsmasq to consume resources, leading to a denial of service. This
 issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04
 LTS. (CVE-2019-14834)");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
