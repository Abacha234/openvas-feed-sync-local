# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892435");
  script_cve_id("CVE-2020-9497", "CVE-2020-9498");
  script_tag(name:"creation_date", value:"2020-11-07 04:00:10 +0000 (Sat, 07 Nov 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-29 19:38:00 +0000 (Mon, 29 Mar 2021)");

  script_name("Debian: Security Advisory (DLA-2435)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2435");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2435");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/guacamole-server");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'guacamole-server' package(s) announced via the DLA-2435 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The server component of Apache Guacamole, a remote desktop gateway, did not properly validate data received from RDP servers. This could result in information disclosure or even the execution of arbitrary code.

CVE-2020-9497

Apache Guacamole does not properly validate data received from RDP servers via static virtual channels. If a user connects to a malicious or compromised RDP server, specially-crafted PDUs could result in disclosure of information within the memory of the guacd process handling the connection.

CVE-2020-9498

Apache Guacamole may mishandle pointers involved in processing data received via RDP static virtual channels. If a user connects to a malicious or compromised RDP server, a series of specially-crafted PDUs could result in memory corruption, possibly allowing arbitrary code to be executed with the privileges of the running guacd process.

For Debian 9 stretch, these problems have been fixed in version 0.9.9-2+deb9u1.

We recommend that you upgrade your guacamole-server packages.

For the detailed security status of guacamole-server please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'guacamole-server' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);