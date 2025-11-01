# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892154");
  script_cve_id("CVE-2020-10802", "CVE-2020-10803");
  script_tag(name:"creation_date", value:"2020-03-23 04:00:10 +0000 (Mon, 23 Mar 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Debian: Security Advisory (DLA-2154)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2154");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2154");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DLA-2154 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following packages CVE(s) were reported against phpmyadmin.

CVE-2020-10802

In phpMyAdmin 4.x before 4.9.5, a SQL injection vulnerability has been discovered where certain parameters are not properly escaped when generating certain queries for search actions in libraries/classes/Controllers/Table/TableSearchController.php. An attacker can generate a crafted database or table name. The attack can be performed if a user attempts certain search operations on the malicious database or table.

CVE-2020-10803

In phpMyAdmin 4.x before 4.9.5, a SQL injection vulnerability was discovered where malicious code could be used to trigger an XSS attack through retrieving and displaying results (in tbl_get_field.php and libraries/classes/Display/Results.php). The attacker must be able to insert crafted data into certain database tables, which when retrieved (for instance, through the Browse tab) can trigger the XSS attack.

For Debian 8 Jessie, these problems have been fixed in version 4:4.2.12-2+deb8u9.

We recommend that you upgrade your phpmyadmin packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);