# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845067");
  script_cve_id("CVE-2021-22945", "CVE-2021-22946", "CVE-2021-22947");
  script_tag(name:"creation_date", value:"2021-09-22 01:00:38 +0000 (Wed, 22 Sep 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5079-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5079-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5079-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1944120");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the USN-5079-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5079-1 fixed vulnerabilities in curl. One of the fixes introduced a
regression on Ubuntu 18.04 LTS. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that curl incorrect handled memory when sending data to
 an MQTT server. A remote attacker could use this issue to cause curl to
 crash, resulting in a denial of service, or possibly execute arbitrary
 code. (CVE-2021-22945)

 Patrick Monnerat discovered that curl incorrectly handled upgrades to TLS.
 When receiving certain responses from servers, curl would continue without
 TLS even when the option to require a successful upgrade to TLS was
 specified. (CVE-2021-22946)

 Patrick Monnerat discovered that curl incorrectly handled responses
 received before STARTTLS. A remote attacker could possibly use this issue
 to inject responses and intercept communications. (CVE-2021-22947)");

  script_tag(name:"affected", value:"'curl' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
