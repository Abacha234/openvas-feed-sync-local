# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704857");
  script_cve_id("CVE-2020-8625");
  script_tag(name:"creation_date", value:"2021-02-19 04:00:06 +0000 (Fri, 19 Feb 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-19 22:15:00 +0000 (Fri, 19 Mar 2021)");

  script_name("Debian: Security Advisory (DSA-4857)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4857");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4857");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bind9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-4857 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow vulnerability was discovered in the SPNEGO implementation affecting the GSSAPI security policy negotiation in BIND, a DNS server implementation, which could result in denial of service (daemon crash), or potentially the execution of arbitrary code.

For the stable distribution (buster), this problem has been fixed in version 1:9.11.5.P4+dfsg-5.1+deb10u3.

We recommend that you upgrade your bind9 packages.

For the detailed security status of bind9 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);