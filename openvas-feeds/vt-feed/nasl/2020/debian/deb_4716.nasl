# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704716");
  script_cve_id("CVE-2020-13401");
  script_tag(name:"creation_date", value:"2020-07-04 03:02:14 +0000 (Sat, 04 Jul 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-27 00:15:00 +0000 (Thu, 27 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4716)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4716");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4716");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/docker.io");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'docker.io' package(s) announced via the DSA-4716 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Etienne Champetier discovered that Docker, a Linux container runtime, created network bridges which by default accept IPv6 router advertisements. This could allow an attacker with the CAP_NET_RAW capability in a container to spoof router advertisements, resulting in information disclosure or denial of service.

For the stable distribution (buster), this problem has been fixed in version 18.09.1+dfsg1-7.1+deb10u2.

We recommend that you upgrade your docker.io packages.

For the detailed security status of docker.io please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'docker.io' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);