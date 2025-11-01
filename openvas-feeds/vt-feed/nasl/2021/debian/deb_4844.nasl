# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704844");
  script_cve_id("CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686", "CVE-2020-25687");
  script_tag(name:"creation_date", value:"2021-02-05 04:00:09 +0000 (Fri, 05 Feb 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-26 18:23:00 +0000 (Fri, 26 Mar 2021)");

  script_name("Debian: Security Advisory (DSA-4844)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4844");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4844");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dnsmasq");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dnsmasq' package(s) announced via the DSA-4844 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Moshe Kol and Shlomi Oberman of JSOF discovered several vulnerabilities in dnsmasq, a small caching DNS proxy and DHCP/TFTP server. They could result in denial of service, cache poisoning or the execution of arbitrary code.

For the stable distribution (buster), these problems have been fixed in version 2.80-1+deb10u1.

We recommend that you upgrade your dnsmasq packages.

For the detailed security status of dnsmasq please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);