# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892145");
  script_cve_id("CVE-2020-10108", "CVE-2020-10109");
  script_tag(name:"creation_date", value:"2020-03-18 10:44:58 +0000 (Wed, 18 Mar 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 02:15:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Debian: Security Advisory (DLA-2145)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2145");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2145-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'twisted' package(s) announced via the DLA-2145 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were was a regression introduced in DLA-2145-1 due to the incorrect application of the upstream patch for CVE-2020-10108 & CVE-2020-10109 regarding a number of HTTP request splitting vulnerabilities in Twisted, an Python event-based framework for building various types of internet applications.

Thanks to Etienne Allovon for the detailed report.

CVE-2020-10108

In Twisted Web through 19.10.0, there was an HTTP request splitting vulnerability. When presented with two content-length headers, it ignored the first header. When the second content-length value was set to zero, the request body was interpreted as a pipelined request.

CVE-2020-10109

In Twisted Web through 19.10.0, there was an HTTP request splitting vulnerability. When presented with a content-length and a chunked encoding header, the content-length took precedence and the remainder of the request body was interpreted as a pipelined request.

For Debian 8 Jessie, these problems have been fixed in version 14.0.2-3+deb8u2.

We recommend that you upgrade your twisted packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'twisted' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);