# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891737");
  script_cve_id("CVE-2019-3871");
  script_tag(name:"creation_date", value:"2019-04-02 20:00:00 +0000 (Tue, 02 Apr 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-05 05:29:00 +0000 (Fri, 05 Apr 2019)");

  script_name("Debian: Security Advisory (DLA-1737)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1737");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-1737");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'pdns' package(s) announced via the DLA-1737 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in PowerDNS Authoritative Server before 4.0.7 and before 4.1.7. An insufficient validation of data coming from the user when building a HTTP request from a DNS query in the HTTP Connector of the Remote backend, allowing a remote user to cause a denial of service by making the server connect to an invalid endpoint, or possibly information disclosure by making the server connect to an internal endpoint and somehow extracting meaningful information about the response.

Only installations using the pdns-backend-remote package are affected.

For Debian 8 Jessie, this problem has been fixed in version 3.4.1-4+deb8u9.

We recommend that you upgrade your pdns packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'pdns' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);