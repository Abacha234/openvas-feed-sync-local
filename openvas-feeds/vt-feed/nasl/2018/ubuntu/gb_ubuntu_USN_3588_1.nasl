# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843467");
  script_cve_id("CVE-2017-9951", "CVE-2018-1000115");
  script_tag(name:"creation_date", value:"2018-03-06 07:40:38 +0000 (Tue, 06 Mar 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3588-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3588-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3588-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'memcached' package(s) announced via the USN-3588-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Shapira discovered an integer overflow issue in Memcached. A remote
attacker could use this to cause a denial of service (daemon crash).
(CVE-2017-9951)

It was discovered that Memcached listened to UDP by default. A remote
attacker could use this as part of a distributed denial of service attack.
(CVE-2018-1000115)");

  script_tag(name:"affected", value:"'memcached' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
