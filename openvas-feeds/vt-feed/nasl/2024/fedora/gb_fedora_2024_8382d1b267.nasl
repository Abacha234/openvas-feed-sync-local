# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887407");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-36461", "CVE-2024-36460", "CVE-2024-22123", "CVE-2024-22122", "CVE-2024-22114");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-08-24 04:04:02 +0000 (Sat, 24 Aug 2024)");
  script_name("Fedora: Security Advisory for zabbix (FEDORA-2024-8382d1b267)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-8382d1b267");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5GDAQJWE2S2VOJV44EHKXFMHCV4JXPD5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zabbix'
  package(s) announced via the FEDORA-2024-8382d1b267 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Zabbix is software that monitors numerous parameters of a network and the
health and integrity of servers");

  script_tag(name:"affected", value:"'zabbix' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
