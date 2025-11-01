# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840830");
  script_cve_id("CVE-2011-4136", "CVE-2011-4137", "CVE-2011-4138", "CVE-2011-4139");
  script_tag(name:"creation_date", value:"2011-12-09 05:22:57 +0000 (Fri, 09 Dec 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1297-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1297-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1297-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-1297-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pall McMillan discovered that Django used the root namespace when storing
cached session data. A remote attacker could exploit this to modify
sessions. (CVE-2011-4136)

Paul McMillan discovered that Django would not timeout on arbitrary URLs
when the application used URLFields. This could be exploited by a remote
attacker to cause a denial of service via resource exhaustion.
(CVE-2011-4137)

Paul McMillan discovered that while Django would check the validity of a
URL via a HEAD request, it would instead use a GET request for the target
of a redirect. This could potentially be used to trigger arbitrary GET
requests via a crafted Location header. (CVE-2011-4138)

It was discovered that Django would sometimes use a request's HTTP Host
header to construct a full URL. A remote attacker could exploit this to
conduct host header cache poisoning attacks via a crafted request.
(CVE-2011-4139)");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
