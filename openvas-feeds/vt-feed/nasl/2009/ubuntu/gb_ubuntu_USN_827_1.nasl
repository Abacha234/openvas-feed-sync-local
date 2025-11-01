# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64827");
  script_cve_id("CVE-2009-2957", "CVE-2009-2958");
  script_tag(name:"creation_date", value:"2009-09-09 00:15:49 +0000 (Wed, 09 Sep 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-827-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-827-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-827-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the USN-827-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IvAin Arce, Pablo HernAin Jorge, Alejandro Pablo Rodriguez, MartAn Coco,
Alberto SoliAto Testa and Pablo Annetta discovered that Dnsmasq did not
properly validate its input when processing TFTP requests for files with
long names. A remote attacker could cause a denial of service or execute
arbitrary code with user privileges. Dnsmasq runs as the 'dnsmasq' user by
default on Ubuntu. (CVE-2009-2957)

Steve Grubb discovered that Dnsmasq could be made to dereference a NULL
pointer when processing certain TFTP requests. A remote attacker could
cause a denial of service by sending a crafted TFTP request.
(CVE-2009-2958)");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
