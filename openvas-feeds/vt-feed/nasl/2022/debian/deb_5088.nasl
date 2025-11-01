# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705088");
  script_cve_id("CVE-2021-36740", "CVE-2022-23959");
  script_tag(name:"creation_date", value:"2022-03-05 02:00:06 +0000 (Sat, 05 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-07 18:16:00 +0000 (Mon, 07 Feb 2022)");

  script_name("Debian: Security Advisory (DSA-5088)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5088");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5088");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/varnish");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'varnish' package(s) announced via the DSA-5088 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-36740

Martin Blix Grydeland discovered that Varnish is vulnerable to request smuggling attacks if the HTTP/2 protocol is enabled.

CVE-2022-23959

James Kettle discovered a request smuggling attack against the HTTP/1 protocol implementation in Varnish.

For the oldstable distribution (buster), these problems have been fixed in version 6.1.1-1+deb10u3.

For the stable distribution (bullseye), these problems have been fixed in version 6.5.1-1+deb11u2.

We recommend that you upgrade your varnish packages.

For the detailed security status of varnish please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'varnish' package(s) on Debian 10, Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);