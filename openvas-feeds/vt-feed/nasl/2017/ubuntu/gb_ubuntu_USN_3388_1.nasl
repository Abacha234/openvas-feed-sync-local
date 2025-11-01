# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843282");
  script_cve_id("CVE-2016-2167", "CVE-2016-8734", "CVE-2017-9800");
  script_tag(name:"creation_date", value:"2017-08-12 05:29:58 +0000 (Sat, 12 Aug 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-3388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3388-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3388-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'subversion' package(s) announced via the USN-3388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joern Schneeweisz discovered that Subversion did not properly handle
host names in 'svn+ssh://' URLs. A remote attacker could use this
to construct a subversion repository that when accessed could run
arbitrary code with the privileges of the user. (CVE-2017-9800)

Daniel Shahaf and James McCoy discovered that Subversion did not
properly verify realms when using Cyrus SASL authentication. A
remote attacker could use this to possibly bypass intended access
restrictions. This issue only affected Ubuntu 14.04 LTS and Ubuntu
16.04 LTS. (CVE-2016-2167)

Florian Weimer discovered that Subversion clients did not properly
restrict XML entity expansion when accessing http(s):// URLs. A remote
attacker could use this to cause a denial of service. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-8734)");

  script_tag(name:"affected", value:"'subversion' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
