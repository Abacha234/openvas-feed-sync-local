# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891945");
  script_cve_id("CVE-2019-16239");
  script_tag(name:"creation_date", value:"2019-10-04 02:00:08 +0000 (Fri, 04 Oct 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-07 23:15:00 +0000 (Wed, 07 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-1945)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1945");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1945");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openconnect' package(s) announced via the DLA-1945 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered by Lukas Kupczyk of the Advanced Research Team at CrowdStrike Intelligence in OpenConnect, an open client for Cisco AnyConnect, Pulse, GlobalProtect VPN. A malicious HTTP server (after its identity certificate has been accepted) can provide bogus chunk lengths for chunked HTTP encoding and cause a heap overflow.

For Debian 8 Jessie, this problem has been fixed in version 6.00-2+deb8u1.

We recommend that you upgrade your openconnect packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'openconnect' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);