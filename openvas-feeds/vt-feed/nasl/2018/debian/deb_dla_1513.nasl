# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891513");
  script_cve_id("CVE-2018-16947", "CVE-2018-16948", "CVE-2018-16949");
  script_tag(name:"creation_date", value:"2018-09-23 22:00:00 +0000 (Sun, 23 Sep 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DLA-1513)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1513");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1513");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openafs' package(s) announced via the DLA-1513 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were discovered in OpenAFS, a distributed file system.

CVE-2018-16947

The backup tape controller process accepts incoming RPCs but does not require (or allow for) authentication of those RPCs. Handling those RPCs results in operations being performed with administrator credentials, including dumping/restoring volume contents and manipulating the backup database.

CVE-2018-16948

Several RPC server routines did not fully initialize their output variables before returning, leaking memory contents from both the stack and the heap. Because the OpenAFS cache manager functions as an Rx server for the AFSCB service, clients are also susceptible to information leakage.

CVE-2018-16949

Several data types used as RPC input variables were implemented as unbounded array types, limited only by the inherent 32-bit length field to 4GB. An unauthenticated attacker could send, or claim to send, large input values and consume server resources waiting for those inputs, denying service to other valid connections.

For Debian 8 Jessie, these problems have been fixed in version 1.6.9-2+deb8u8.

We recommend that you upgrade your openafs packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'openafs' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);