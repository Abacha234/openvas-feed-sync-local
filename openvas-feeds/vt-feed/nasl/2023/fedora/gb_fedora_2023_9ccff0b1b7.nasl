# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884815");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-21911", "CVE-2023-21919", "CVE-2023-21920", "CVE-2023-21929", "CVE-2023-21933", "CVE-2023-21935", "CVE-2023-21940", "CVE-2023-21945", "CVE-2023-21946", "CVE-2023-21947", "CVE-2023-21953", "CVE-2023-21955", "CVE-2023-21962", "CVE-2022-4899", "CVE-2023-22005", "CVE-2023-22008", "CVE-2023-22033", "CVE-2023-22038", "CVE-2023-22046", "CVE-2023-22048", "CVE-2023-22053", "CVE-2023-22054", "CVE-2023-22056", "CVE-2023-22057", "CVE-2023-22058");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 01:19:00 +0000 (Fri, 07 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:34 +0000 (Sat, 16 Sep 2023)");
  script_name("Fedora: Security Advisory for community-mysql (FEDORA-2023-9ccff0b1b7)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-9ccff0b1b7");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/C63HAGVLQA6FJNDCHR7CNZZL6VSLILB2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'community-mysql'
  package(s) announced via the FEDORA-2023-9ccff0b1b7 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. The base package
contains the standard MySQL client programs and generic MySQL files.");

  script_tag(name:"affected", value:"'community-mysql' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
